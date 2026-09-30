"""Point 3: nmap XML parsing must keep product/version for every service."""

from scan_service import _parse_nmap_xml

XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0">
          <cpe>cpe:/a:igor_sysoev:nginx:1.24.0</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="2323">
        <state state="open"/>
        <service name="unknown"/>
        <script id="banner" output="  hello banner  "/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="open"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed"/>
        <service name="telnet"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_service_without_children_keeps_product_and_version():
    res = _parse_nmap_xml(XML)
    assert res[22] == {
        "product": "OpenSSH", "version": "8.9p1", "extrainfo": "Ubuntu",
        "banner": "", "cpe": "", "name": "ssh",
    }


def test_service_with_cpe():
    res = _parse_nmap_xml(XML)
    assert res[80]["product"] == "nginx"
    assert res[80]["cpe"] == "cpe:/a:igor_sysoev:nginx:1.24.0"


def test_banner_script_used_when_no_product():
    assert _parse_nmap_xml(XML)[2323]["banner"] == "hello banner"


def test_port_without_service_element():
    assert _parse_nmap_xml(XML)[9999]["name"] == ""


def test_closed_ports_are_skipped():
    assert 23 not in _parse_nmap_xml(XML)


def test_invalid_xml_reports_error():
    assert "_error" in _parse_nmap_xml("<nmaprun>")
