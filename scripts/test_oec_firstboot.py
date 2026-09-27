import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
UNIT = ROOT / "firmware/oec/rootfs/etc/systemd/system/ty-gateway-firstboot.service"
SCRIPT = ROOT / "firmware/oec/rootfs/usr/local/libexec/ty-gateway-firstboot"


class FirstbootUnitTests(unittest.TestCase):
    def test_firstboot_unit_keeps_system_configuration_writable(self):
        unit = UNIT.read_text(encoding="utf-8")
        self.assertIsNone(
            re.search(r"(?m)^ProtectSystem=", unit),
            "firstboot provisions users and /etc/ty-gateway; ProtectSystem can block those writes",
        )

    def test_firstboot_script_still_documents_the_write_requirement(self):
        script = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("groupadd --system tygateway", script)
        self.assertIn("install -d -m 0750 -o root -g tygateway /etc/ty-gateway", script)


if __name__ == "__main__":
    unittest.main()
