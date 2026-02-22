#!/system/bin/sh
# Sample Magisk Module Installation Script
#
# NOTE:
# Do NOT set SKIPUNZIP=1 here. Let Magisk handle unzipping the module zip.
# Some devices/versions don't have a working `unzip` binary in the installer
# environment, and manually calling it can surface as a generic "unzip error"
# in Magisk UI even though the zip itself is fine.

# 检查 Zygisk 是否启用
case "${ZYGISK_ENABLED:-}" in
  1|true|TRUE|yes|YES)
    ui_print "- Zygisk is enabled"
    ;;
  *)
    ui_print "- Magisk built-in Zygisk is not enabled (OK if you use Zygisk Next)"
    ui_print "  If you're using Zygisk Next, keep Magisk Zygisk disabled to avoid conflicts."
    ;;
esac

# 设置权限
ui_print "- Setting permissions"
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm_recursive "$MODPATH/zygisk" 0 0 0755 0755

ui_print "- Installation complete"
ui_print "  Please reboot to activate the module"

