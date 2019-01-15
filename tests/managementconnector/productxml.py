PRODUCT_XML_CONTENTS = """<?xml version="1.0" encoding="UTF-8"?>
<product>
    <name>TANDBERG Video Communication Server</name>
    <code>X</code>
    <version>
        <major>12</major>
        <minor>6</minor>
        <maintenance>0</maintenance>
        <release>
            <type>PreAlpha</type>
            <version>0</version>
        </release>
    </version>
    <snmp>
        <system_oid>.1.3.6.1.4.1.5596.130.6.4.1</system_oid>
    </snmp>
    <software>
        <id>s42700</id>
        <encryption>True</encryption>
        <option_prefix>116341</option_prefix>
        <uses_installwizard>True</uses_installwizard>
    </software>
    <build>
        <date>2018-11-21 11:30</date>
        <revision>wood_v2018.11.16-1-g2871927</revision>
        <!-- type is one of Release/TEST SW -->
        <type>Test SW</type>
        <builder>michkenn</builder>
    </build>
    <hardware>
        <network>
            <interface>
                <name>LAN1</name>
                <device>eth0</device>
                <virtual_interfaces>64</virtual_interfaces>
            </interface>
            <interface>
                <name>LAN2</name>
                <device>eth1</device>
                <virtual_interfaces>0</virtual_interfaces>
            </interface>
        </network>
    </hardware>
</product>
"""