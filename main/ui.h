#pragma once

// Compose the wallet/outbox home screen on the TTGO T-Display. Safe to call
// while the screen is asleep: the framebuffer is flushed when a button wakes
// the panel.
void display_refresh();

// Periodic refresh task for power, Wi-Fi, wallet, and Find My status.
void display_ui_task(void *arg);
