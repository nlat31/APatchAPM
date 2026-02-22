#pragma once

namespace envcloak {
namespace native_hook {

/**
 * 初始化 Native Hook 模块
 *
 * @return true if success
 */
bool initialize();

/**
 * Install hooks that should be inherited across fork.
 *
 * Designed to be called in Zygote as early as possible to cover init_array checks.
 */
void install_early_hooks();

/**
 * Install app-process hooks.
 */
void install_hooks();

} // namespace native_hook
} // namespace envcloak

