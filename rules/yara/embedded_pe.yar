// Generic, first-party rules (no third-party signatures are bundled).

rule embedded_pe_dos_stub
{
    meta:
        description = "A second DOS/PE header is embedded inside the file (dropper, installer, or a PE carried in resources, overlay or data)."
        severity = "low"
        confidence = "low"
        category = "anomaly"
        attack = "T1027.009"
    strings:
        $stub = "This program cannot be run in DOS mode"
    condition:
        // Inside a PE: more than its own stub. In any other file: any stub
        // after the start.
        (uint16(0) == 0x5A4D and #stub > 1) or
        (uint16(0) != 0x5A4D and $stub in (2..filesize))
}
