// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// hw/lockdown.rs — Post-boot security hardening
// 100% Rust, no-std, no-alloc
//
// KasSigner is air-gapped. WiFi, Bluetooth, USB OTG, and JTAG have
// no legitimate use. This module shuts down unused peripherals and
// reports the permanent hardware security state in every build.
//
// Two phases:
//   early_lockdown()  — called immediately after esp_hal::init(),
//                       before any peripheral setup. Kills radios.
//   post_boot_lockdown() — called after firmware verification,
//                          before the main loop. Kills USB data + JTAG.
//
// Software register writes are defense in depth, not a hardware root of
// trust. Permanent Secure Boot, flash encryption, and JTAG disablement are
// read from eFuses and reported as optional hardware hardening. They are not
// treated as enabled unless the release pipeline actually provisions an ESP
// hardware root of trust. This module never burns eFuses.

use crate::log;
use esp_hal::efuse::{
    Efuse, DIS_PAD_JTAG, DIS_USB_JTAG, SECURE_BOOT_EN,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardwareSecurityState {
    pub secure_boot: bool,
    pub flash_encryption: bool,
    pub pad_jtag_disabled: bool,
    pub usb_jtag_disabled: bool,
}

impl HardwareSecurityState {
    pub const fn production_ready(self) -> bool {
        self.secure_boot
            && self.flash_encryption
            && self.pad_jtag_disabled
            && self.usb_jtag_disabled
    }
}

/// Read the ESP32-S3's permanent security configuration. This operation is
/// read-only and cannot change or burn an eFuse.
pub fn hardware_security_state() -> HardwareSecurityState {
    HardwareSecurityState {
        secure_boot: Efuse::read_field_le::<u8>(SECURE_BOOT_EN) != 0,
        flash_encryption: Efuse::flash_encryption(),
        pad_jtag_disabled: Efuse::read_field_le::<u8>(DIS_PAD_JTAG) != 0,
        usb_jtag_disabled: Efuse::read_field_le::<u8>(DIS_USB_JTAG) != 0,
    }
}

/// Report optional permanent hardware hardening. Firmware authenticity is
/// enforced separately by the mandatory production Schnorr verification;
/// these eFuses must not become a boot requirement until the release pipeline
/// can generate ESP Secure Boot-compatible images and provision devices safely.
pub fn report_hardware_security_state() {
    let state = hardware_security_state();
    log!(
        "   [SEC] eFuses: secure_boot={} flash_encryption={} pad_jtag_off={} usb_jtag_off={}",
        state.secure_boot,
        state.flash_encryption,
        state.pad_jtag_disabled,
        state.usb_jtag_disabled
    );

    if !state.production_ready() {
        log!("   [WARN] Optional ESP hardware hardening is not fully provisioned");
    }
}

// ═══════════════════════════════════════════════════════════════════
// System register addresses (ESP32-S3 TRM Ch.7)
// ═══════════════════════════════════════════════════════════════════

/// Peripheral clock enable register 0
const SYSTEM_PERIP_CLK_EN0: u32 = 0x600C_0018;
/// Peripheral clock enable register 1
const SYSTEM_PERIP_CLK_EN1: u32 = 0x600C_001C;
/// Peripheral reset register 0
const SYSTEM_PERIP_RST_EN0: u32 = 0x600C_0020;
/// Peripheral reset register 1
const SYSTEM_PERIP_RST_EN1: u32 = 0x600C_0024;

/// WiFi clock enable (PERIP_CLK_EN0 bit 0 + dedicated regs)
const SYSTEM_WIFI_CLK_EN: u32 = 0x600C_0090;
/// Bluetooth clock register
const SYSTEM_BT_LPCK_DIV_FRAC: u32 = 0x600C_00A8;

// PERIP_CLK_EN0 bits
const USB_CLK_EN: u32 = 1 << 23; // USB OTG

// PERIP_CLK_EN1 bits
const USB_DEVICE_CLK_EN: u32 = 1 << 10; // USB Serial/JTAG device

/// USB Serial/JTAG configuration register
const USB_SERIAL_JTAG_CONF0: u32 = 0x6003_8044;

/// GPIO JTAG enable register
/// Writing 0 to JTAG-related bits in the USB_SERIAL_JTAG peripheral
/// disables the JTAG bridge
const USB_SERIAL_JTAG_BASE: u32 = 0x6003_8000;

// ═══════════════════════════════════════════════════════════════════
// Register helpers
// ═══════════════════════════════════════════════════════════════════

#[inline(always)]
unsafe fn reg_read(addr: u32) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

#[inline(always)]
unsafe fn reg_write(addr: u32, val: u32) {
    core::ptr::write_volatile(addr as *mut u32, val);
}

#[inline(always)]
unsafe fn reg_clear_bits(addr: u32, bits: u32) {
    let v = reg_read(addr);
    reg_write(addr, v & !bits);
}

#[inline(always)]
unsafe fn reg_set_bits(addr: u32, bits: u32) {
    let v = reg_read(addr);
    reg_write(addr, v | bits);
}

// ═══════════════════════════════════════════════════════════════════
// Phase 1: Early lockdown — kill radios immediately after init
// ═══════════════════════════════════════════════════════════════════

/// Disable WiFi, Bluetooth, and USB OTG clocks.
/// Called immediately after `esp_hal::init()`, before any peripheral setup.
/// These peripherals have no legitimate use in an air-gapped signer.
pub fn early_lockdown() {
    unsafe {
        // ── Kill WiFi + Bluetooth clocks ──
        // Zero the WiFi/modem clock register — gates all radio clocks.
        // NOTE: This register is shared. If SD card fails after this,
        // do a hard power cycle — a prior panic may have left SDHOST
        // in a bad state that persists across soft resets.
        reg_write(SYSTEM_WIFI_CLK_EN, 0);

        // Zero the BT low-power clock divider
        reg_write(SYSTEM_BT_LPCK_DIV_FRAC, 0);

        // ── Kill USB OTG ──
        // Gate USB OTG peripheral clock (not USB Serial/JTAG — that's
        // used for flashing/monitoring, killed in post_boot_lockdown)
        reg_clear_bits(SYSTEM_PERIP_CLK_EN0, USB_CLK_EN);
        reg_set_bits(SYSTEM_PERIP_RST_EN0, USB_CLK_EN);
    }

    log!("   [SEC] Radios disabled (WiFi, BT, USB OTG)");
}

// ═══════════════════════════════════════════════════════════════════
// Phase 2: Post-boot lockdown — kill USB data + JTAG after verify
// ═══════════════════════════════════════════════════════════════════

/// Reduce the USB Serial/JTAG peripheral attack surface.
/// Called after firmware verification, before the main loop.
///
/// In dev mode (not production), USB Serial is kept alive for UART
/// monitoring. In production, everything is killed.
///
/// Permanent JTAG disablement is reported above. Register writes here must
/// not be described as equivalent to permanent eFuse provisioning.
pub fn post_boot_lockdown() {
    unsafe {
        // ── Reduce USB/JTAG pin surface ──
        // The USB_SERIAL_JTAG peripheral has a JTAG-to-USB bridge.
        // Clear the exchange pin override to disconnect JTAG from pins.
        // This prevents using USB to access JTAG even if the peripheral
        // clock is still running (needed for UART in dev mode).
        let conf0 = reg_read(USB_SERIAL_JTAG_CONF0);
        // Bit 13: USB_SERIAL_JTAG_USB_PAD_ENABLE — controls whether
        // the USB pads are connected. We leave this for UART.
        // Bit 2: EXCHANGE_PINS — if set, swaps D+/D- (irrelevant here)
        // Write 0 to bits [4:3] (VDD_SPI_AS_GPIO, PULLUP_DM) to reduce
        // attack surface on the USB pins.
        reg_write(USB_SERIAL_JTAG_CONF0, conf0 & !(0x3 << 3));

        // ── Production: kill USB Serial/JTAG entirely ──
        #[cfg(feature = "production")]
        {
            // Gate USB Serial/JTAG device clock
            reg_clear_bits(SYSTEM_PERIP_CLK_EN1, USB_DEVICE_CLK_EN);
            // Hold in reset
            reg_set_bits(SYSTEM_PERIP_RST_EN1, USB_DEVICE_CLK_EN);
        }
    }

    #[cfg(feature = "production")]
    log!("   [SEC] USB Serial/JTAG disabled (production)");

    #[cfg(not(feature = "production"))]
    log!("   [SEC] USB/JTAG surface reduced (USB UART kept for dev)");
}

#[cfg(test)]
mod tests {
    use super::HardwareSecurityState;

    #[test]
    fn production_policy_requires_every_hardware_control() {
        let ready = HardwareSecurityState {
            secure_boot: true,
            flash_encryption: true,
            pad_jtag_disabled: true,
            usb_jtag_disabled: true,
        };
        assert!(ready.production_ready());

        for missing in 0..4 {
            let mut state = ready;
            match missing {
                0 => state.secure_boot = false,
                1 => state.flash_encryption = false,
                2 => state.pad_jtag_disabled = false,
                _ => state.usb_jtag_disabled = false,
            }
            assert!(!state.production_ready());
        }
    }
}
