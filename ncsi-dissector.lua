
--------------------------------------------------------------------------------------------
--                                                                                        --
-- NC-SI(Network Controller Sideband Interface) (DSP0222 v1.0.1) dissector                --
-- Author   : Xu Zenghui(zenghui.xu@nokia-sbell.com)                                      --
-- Date     : 2019-05-16                                                                  --
-- Version  : 0.1.0                                                                       --
--                                                                                        --
-- TODO                                                                                   --
--     1. OEM command support                                                             --
--     2. Expert info support                                                             --
--     3. Show packet details in info column                                              --
--                                                                                        --
---------------------------------------------------------------------------------------------


NCSI_ETHER_TYPE = 0x88F8
ncsi_proto = Proto("NC-SI", "Network Controller Sideband Interface Protocol")

---------------------------------------------------------------------------------------------
--Global definitions and helper functions

pkt_types = {
    [0x00]  = "Clear Initial State Command (0x00)",
    [0x80]  = "Clear Initial State Response (0x80)",
    [0x01]  = "Select Package Command (0x01)",
    [0x81]  = "Select Package Response (0x81)",
    [0x02]  = "Deselect Package Command (0x02)",
    [0x82]  = "Deselect Package Response (0x82)",
    [0x03]  = "Enable Channel Command (0x03)",
    [0x83]  = "Enable Channel Response (0x83)",
    [0x04]  = "Disable Channel Command (0x04)",
    [0x84]  = "Disable Channel Response (0x84)",
    [0x05]  = "Reset Channel Command (0x05)",
    [0x85]  = "Reset Channel Response (0x85)",
    [0x06]  = "Enable Channel Network TX Command (0x06)",
    [0x86]  = "Enable Channel Network TX Response (0x86)",
    [0x07]  = "Disable Channel Network TX Command (0x07)",
    [0x87]  = "Disable Channel Network TX Response (0x87)",
    [0x08]  = "AEN Enable Command (0x08)",
    [0x88]  = "AEN Enable Response (0x88)",
    [0x09]  = "Set Link Command (0x09)",
    [0x89]  = "Set Link Response (0x89)",
    [0x0A]  = "Get Link Status Command (0x0A)",
    [0x8A]  = "Get Link Status Response (0x8A)",
    [0x0B]  = "Set VLAN Filter Command (0x0B)",
    [0x8B]  = "Set VLAN Filter Response (0x8B)",
    [0x0C]  = "Enable VLAN Command (0x0C)",
    [0x8C]  = "Enable VLAN Response (0x8C)",
    [0x0D]  = "Disable VLAN Command (0x0D)",
    [0x8D]  = "Disable VLAN Response (0x8D)",
    [0x0E]  = "Set MAC Address Command (0x0E)",
    [0x8E]  = "Set MAC Address Response (0x8E)",
    [0x10]  = "Enable Broadcast Filter Command (0x10)",
    [0x90]  = "Enable Broadcast Filter Response (0x90)",
    [0x11]  = "Disable Broadcast Filter Command (0x11)",
    [0x91]  = "Disable Broadcast Filter Response (0x91)",
    [0x12]  = "Enable Global Multicast Filter Command (0x12)",
    [0x92]  = "Enable Global Multicast Filter Response (0x92)",
    [0x13]  = "Disable Global Multicast Filter Command (0x13)",
    [0x93]  = "Disable Global Multicast Filter Response (0x93)",
    [0x14]  = "Set NC-SI Flow Control Command (0x14)",
    [0x94]  = "Set NC-SI Flow Control Response (0x94)",
    [0x15]  = "Get Version ID Command (0x15)",
    [0x95]  = "Get Version ID Response (0x95)",
    [0x16]  = "Get Capabilities Command (0x16)",
    [0x96]  = "Get Capabilities Response (0x96)",
    [0x17]  = "Get Parameters Command (0x17)",
    [0x97]  = "Get Parameters Response (0x97)",
    [0x18]  = "Get Controller Packet Statistics Command (0x18)",
    [0x98]  = "Get Controller Packet Statistics Response (0x98)",
    [0x19]  = "Get NC-SI Statistics Command (0x19)",
    [0x99]  = "Get NC-SI Statistics Response (0x99)",
    [0x1A]  = "Get NC-SI Pass-through Statistics Command (0x1A)",
    [0x9A]  = "Get NC-SI Pass-through Statistics Response (0x9A)",
    [0x50]  = "OEM Command (0x50)",
    [0xD0]  = "OEM Response (0xD0)",
    [0xFF]  = "AEN(Asynchronous Event Notification) (0xFF)"
  }

e1_d0 = {
    [0] = "Disabled",
    [1] = "Enabled"
}
e0_d1 = {
    [0] = "Enabled",
    [1] = "Disabled"
}

y1_n0 = {
    [0] = "No",
    [1] = "Yes"
}

v1_i0 = {
    [0] = "Valid",
    [1] = "Invalid"
}

std_resp_code = {
    [0x0000] = "Command Completed",
    [0x0001] = "Command Failed",
    [0x0002] = "Command Unavailable",
    [0x0003] = "Command Unsupported"
    -- 0x8000–0xFFFF "Vendor/OEM-specific"
  }

std_reason_code = {
    [0x0000] = "No Error/No Reason Code",
    [0x0001] = "Interface Initialization Required",
    [0x0002] = "Parameter Is Invalid, Unsupported, or Out-of-Range",
    [0x0003] = "Channel Not Ready",
    [0x0004] = "Package Not Ready",
    [0x0005] = "Invalid payload length",
    [0x7FFF] = "Unknown / Unsupported Command Type"
    -- 0x8000–0xFFFF "OEM Reason Code"
  }

local response_code = ProtoField.uint16("ncsi.response_code", "Response Code", base.HEX, std_resp_code)
local reason_code   = ProtoField.uint16("ncsi.reason_code", "Reason Code", base.HEX, std_reason_code)

local function dissect_std_response_code(tvbuf, pktinfo, tree)
    -- Get Response Code value
  local value = tvbuf(0, 2):uint()
  local text = nil
  if((value >= 0x8000) and (value <= 0xFFFF)) then
    text = "Vendor/OEM-specific"
  else
    text = std_resp_code[value]
  end

  if text == nil then
    text = "Unknown Response Code"
  end 
  
  tree:add(response_code, tvbuf(0, 2)):set_text(string.format("Response Code: %s (0x%04x)", text, value))
  if value ~= 0x0 then
    pktinfo.cols.info:append(" Result: "..text)
  end

  -- Mark packet in red if Response Code is not 0
  set_color_filter_slot(1, "ncsi.response_code != 0x0")
end  

local function dissect_std_reason_code(tvbuf, pktinfo, tree)
  -- Get Reason Code value
  local value = tvbuf(0, 2):uint()
  local text = nil
  if((value >= 0x8000) and (value <= 0xFFFF)) then
    text = "OEM Reason Code"
  else
    text = std_reason_code[value]
  end

  if text == nil then
    text = "Unknown Reason Code"
  end
  
  tree:add(reason_code, tvbuf(0, 2)):set_text(string.format("Reason Code: %s (0x%04x)", text, value))
end


local function dissect_resp_reason_code(tvbuf, pktinfo, tree, cmd, codes)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen < 4 then return end
  
  -- Standard Response/Reason Code 
  if (cmd == nil) or (codes == nil) then
    dissect_std_response_code(tvbuf(0, 2):tvb(), pktinfo, tree)
    dissect_std_reason_code(tvbuf(2, 2):tvb(), pktinfo, tree)
    return
  end

  dissect_std_response_code(tvbuf(0, 2):tvb(), pktinfo, tree)
  -- Command-Specific Reason Codes
  local text = nil
  local msbyte = tvbuf(2, 1):uint()
  local lsbyte = tvbuf(3, 1):uint()
  local value  = tvbuf(2, 2):uint()
  if msbyte ~= cmd then
    dissect_std_reason_code(tvbuf(2, 2):tvb(), pktinfo, tree)
    return
  end
  
  text = codes[lsbyte]
  if text == nil then
      text = "Unknown Reason Code"
  end    
  
  tree:add(reason_code, tvbuf(2, 2)):set_text(string.format("Reason Code: %s (0x%04x)", text, value))
  pktinfo.cols.info:append("  Reason: "..text)
end


local function common_dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  local checksum = tvbuf(0, 4):uint()
  tree:add(tvbuf(0, 4), "Checksum: "..string.format("0x%08x", checksum))
end

local function rep_common_dissector(tvbuf, pktinfo, tree) 
  dissect_resp_reason_code(tvbuf, pktinfo, tree)  
  common_dissector(tvbuf(4, 4):tvb(), pktinfo, tree)
end


---------------------------------------------------------------------------------------------
-- NC-SI Dissector 

local mcid          = ProtoField.uint8("ncsi.mcid", "Management Controller ID", base.DEC)
local header_rev    = ProtoField.uint8("ncsi.hdr_rev", "Header Revision", base.DEC)
local iid           = ProtoField.uint8("ncsi.iid", "Instance ID", base.DEC)
local ctr_pkt_type  = ProtoField.uint8("ncsi.type", "Control Packet Type", base.HEX, pkt_types)
local chid          = ProtoField.uint8("ncsi.chid", "Channel ID", base.HEX)
local internal_chid = ProtoField.uint8("ncsi.iid", "Internal Channel ID", base.DEC, nil, 0x1F)
local package_id    = ProtoField.uint8("ncsi.iid", "Package ID", base.DEC, nil, 0xE0)
local payload_len   = ProtoField.uint16("ncsi.payload_len", "Payload Length", base.DEC, nil, 0xFFF)


ncsi_proto.fields = {
    mcid, header_rev, iid, ctr_pkt_type, chid, internal_chid, package_id, payload_len,
    response_code, reason_code
  }

payload_dissectors = DissectorTable.new("ncsi.type", "NC-SI command", ftypes.UINT8, base.HEX)


-- @brif This function disssects NC-SI Control Packet Header.
-- @tvbuf The buffer to dissect.
-- @pktinfo The packet info.
-- @header The tree on which to add the header items.

local function ncsi_dissect_header(tvbuf, pktinfo, header)
  
  header:add(mcid, tvbuf(0, 1))
  header:add(header_rev, tvbuf(1, 1))
  header:add(iid, tvbuf(3, 1))
  header:add(ctr_pkt_type, tvbuf(4, 1))
  chid_tree = header:add(chid, tvbuf(5, 1))
  chid_tree:add(internal_chid, tvbuf(5, 1))
  chid_tree:add(package_id, tvbuf(5, 1))
  header:add(payload_len, tvbuf(6, 2))

end

function ncsi_proto.dissector(tvbuf, pktinfo, tree)
  
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end

  local pkt_type = tvbuf(4, 1):uint()
  -- set the protocol column to show our protocol name
  pktinfo.cols.protocol:set("NC-SI")  
  pktinfo.cols.info:set(pkt_types[pkt_type])
  
  local subtree = tree:add(ncsi_proto, tvbuf(0,pktlen), "Network Controller Sideband Interface Protocol Data")
  -- add header tree iterm
  local header_tree = subtree:add(tvbuf(0, 16), "Control Packet Header")
  -- add payload tree iterm
  local payload_tree = subtree:add(tvbuf(16, pktlen - 16), pkt_types[pkt_type])
  
  -- dissect the Control Packet Header
  ncsi_dissect_header(tvbuf, pktinfo, header_tree)
  
  -- dissect the Control Packet Payload
  local offset = 16
  if (pkt_type >= 0x80) and (pkt_type ~= 0xFF) then
    -- for response packets, first add response code and reason code
    --payload_tree:add(response_code, tvbuf(16, 2))
    --payload_tree:add(reason_code, tvbuf(18, 2))
    --offset = 20
  end  

  payload_dissectors:try(pkt_type, tvbuf(offset, pktlen - offset):tvb(), pktinfo, payload_tree)
  
  -- Coloring
  -- Mark AEN packets in yellow
  set_color_filter_slot(8, "ncsi.type == 0xff")
end

local ether_type = DissectorTable.get("ethertype")
ether_type:add(NCSI_ETHER_TYPE, ncsi_proto)


---------------------------------------------------------------------------------------------
-- Dissector for Clear Initial State Command (0x00)

ncsi_cisc  = Proto("NC-SI-CISC", pkt_types[0x00])

function ncsi_cisc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x00, ncsi_cisc)


---------------------------------------------------------------------------------------------
-- Dissector for Clear Initial State Response (0x80)

ncsi_cisr  = Proto("NC-SI-CISR", pkt_types[0x80])

function ncsi_cisr.dissector(tvbuf, pktinfo, tree)
  rep_common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x80, ncsi_cisr)


---------------------------------------------------------------------------------------------
-- Dissector for Select Package Command (0x01)

ncsi_spc = Proto("NC-SI-SPC", pkt_types[0x01])

local hadb      = ProtoField.uint8("ncsi.spc.had", "Hardware Arbitration", base.DEC, e0_d1, 0x1)

ncsi_spc.fields = {
    hadb
}

function ncsi_spc.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  tree:add(hadb, tvbuf(3, 1))
  local checksum = tvbuf(4, 4):uint()
  tree:add(tvbuf(4, 4), "Checksum: "..string.format("0x%08x", checksum))
end

payload_dissectors:add(0x01, ncsi_spc)



---------------------------------------------------------------------------------------------
-- Dissector for Select Package Response (0x81)

ncsi_spr = Proto("NC-SI-SPR", pkt_types[0x81])

function ncsi_spr.dissector(tvbuf, pktinfo, tree)
  rep_common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x81, ncsi_spr)





---------------------------------------------------------------------------------------------
-- Dissector for Deselect Package Command (0x02)

ncsi_dpc = Proto("NC-SI-DPC", pkt_types[0x02])

function ncsi_dpc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x02, ncsi_dpc)



---------------------------------------------------------------------------------------------
-- Dissector for Deselect Package Response (0x82)

ncsi_dpr  = Proto("NC-SI-DPR", pkt_types[0x82])

function ncsi_dpr.dissector(tvbuf, pktinfo, tree)
  rep_common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x82, ncsi_dpr)



---------------------------------------------------------------------------------------------
-- Dissector for Enable Channel Command (0x03)

ncsi_ecc  = Proto("NC-SI-ECC", pkt_types[0x03])

function ncsi_ecc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x03, ncsi_ecc)





---------------------------------------------------------------------------------------------
-- Dissector for Enable Channel Response (0x83)

ncsi_ecr  = Proto("NC-SI-ECR", pkt_types[0x83])

function ncsi_ecr.dissector(tvbuf, pktinfo, tree)
  rep_common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x83, ncsi_ecr)




---------------------------------------------------------------------------------------------
-- Dissector for Disable Channel Command (0x04)

ncsi_dcc  = Proto("NC-SI-DCC", pkt_types[0x04])

local ald      = ProtoField.bool("ncsi.dcc.ald", "Allow Link Down", 8, nil, 0x1)

ncsi_dcc.fields = {
    ald
}

function ncsi_dcc.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  tree:add(ald, tvbuf(3, 1))
  local checksum = tvbuf(4, 4):uint()
  tree:add(tvbuf(4, 4), "Checksum: "..string.format("0x%08x", checksum))
end

payload_dissectors:add(0x04, ncsi_dcc)





---------------------------------------------------------------------------------------------
-- Dissector for Enable Disable Channel Response (0x84)

ncsi_dcr  = Proto("NC-SI-DCR", pkt_types[0x84])

function ncsi_dcr.dissector(tvbuf, pktinfo, tree)
  rep_common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x84, ncsi_dcr)




---------------------------------------------------------------------------------------------
-- Dissector for Reset Channel Command (0x05)

ncsi_rcc  = Proto("NC-SI-RCC", pkt_types[0x05])

function ncsi_rcc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf(4, 4):tvb(), pktinfo, tree)
end

payload_dissectors:add(0x05, ncsi_rcc)


---------------------------------------------------------------------------------------------
-- Dissector for Reset Channel Response (0x85)

ncsi_rcr  = Proto("NC-SI-RCR", pkt_types[0x85])

function ncsi_rcr.dissector(tvbuf, pktinfo, tree)
  rep_common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x85, ncsi_rcr)


---------------------------------------------------------------------------------------------
-- Dissector for Enable Channel Network TX Command (0x06)

ncsi_ecntxc = Proto("NC-SI-ECNTXC", pkt_types[0x06])

function ncsi_ecntxc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x06, ncsi_ecntxc)



---------------------------------------------------------------------------------------------
-- Dissector for Enable Channel Network TX Response (0x86)

ncsi_ecntxr  = Proto("NC-SI-ECNTXR", pkt_types[0x86])

function ncsi_ecntxr.dissector(tvbuf, pktinfo, tree)
  rep_common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x86, ncsi_ecntxr)





---------------------------------------------------------------------------------------------
-- Dissector for Disable Channel Network TX Command (0x07)

ncsi_dcntxc = Proto("NC-SI-DCNTXC", pkt_types[0x07])

function ncsi_dcntxc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x07, ncsi_dcntxc)



---------------------------------------------------------------------------------------------
-- Dissector for Disable Channel Network TX Response (0x87)

ncsi_dcntxr  = Proto("NC-SI-DCNTXR", pkt_types[0x87])

function ncsi_dcntxr.dissector(tvbuf, pktinfo, tree)
  rep_common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x87, ncsi_dcntxr)




---------------------------------------------------------------------------------------------
-- Dissector for AEN Enable Command (0x08)

ncsi_aenec  = Proto("NC-SI-AENEC", "AEN Enable Command (0x08)")

local aen_mcid    = ProtoField.uint8("ncsi.aenec.mcid", "AEN MC ID", base.HEX)

-- Table 38 – Format of AEN Control
local aen_ctrl      = ProtoField.uint32("ncsi.daenc.aen", "AEN Control", base.HEX)
local lsc_aen_ctrl  = ProtoField.uint32("ncsi.daenc.lsc", "Link Status Change AEN control", base.DEC, e1_d0, 0x1)
local cr_aen_ctrl   = ProtoField.uint32("ncsi.daenc.cr", "Configuration Required AEN control", base.DEC, e1_d0, 0x2)
local hsc_aen_ctrl  = ProtoField.uint32("ncsi.daenc.hsc", "Host NC Driver Status Change AEN control", base.DEC, e1_d0, 0x4)
local reserved      = ProtoField.uint32("ncsi.daenc.rsvd", "Reserved", base.DEC, nil, 0xFFF8)
local oem_aen_ctrl  = ProtoField.uint32("ncsi.daenc.oem", "OEM-specific AEN control", base.DEC, nil, 0xFFFF0000)

ncsi_aenec.fields = {
    aen_mcid,
    aen_ctrl, lsc_aen_ctrl, cr_aen_ctrl, hsc_aen_ctrl, reserved, oem_aen_ctrl,
}

local function dissect_aen_ctrl(tvbuf, pktinfo, tree)
  tree:add(lsc_aen_ctrl, tvbuf(0, 4))
  tree:add(cr_aen_ctrl, tvbuf(0, 4))
  tree:add(hsc_aen_ctrl, tvbuf(0, 4))
  tree:add(reserved, tvbuf(0, 4))
  tree:add(oem_aen_ctrl, tvbuf(0, 4))
end

function ncsi_aenec.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  tree:add(aen_mcid, tvbuf(3, 1))
  
    -- add AEN Control tree iterm
  local aen_ctrl_tree = tree:add(aen_ctrl, tvbuf(4, 4))
  dissect_aen_ctrl(tvbuf(4, 4):tvb(), pktinfo, aen_ctrl_tree)
  local checksum = tvbuf(8, 4):uint()
  tree:add(tvbuf(8, 4), "Checksum: "..string.format("0x%08x", checksum))
end

payload_dissectors:add(0x08, ncsi_aenec)




---------------------------------------------------------------------------------------------
-- Dissector for AEN Enable Response (0x88)

ncsi_aener  = Proto("NC-SI-AENER", pkt_types[0x88])

function ncsi_aener.dissector(tvbuf, pktinfo, tree)
  rep_common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x88, ncsi_aener)




---------------------------------------------------------------------------------------------
-- Dissector for Set Link Command (0x09)

ncsi_slc  = Proto("NC-SI-SLC", "Set Link Command (0x09)")


-- Table 41 – Set Link Bit Definitions

local auto_nego     = ProtoField.uint32("ncsi.slc.auto_nego", "Auto Negotiation", base.DEC, e1_d0, 0x1)
local speed_10      = ProtoField.uint32("ncsi.slc.sp10", "enable 10 Mbps", base.DEC, e1_d0, 0x2)
local speed_100     = ProtoField.uint32("ncsi.slc.sp100", "enable 100 Mbps", base.DEC, e1_d0, 0x4)
local speed_1000    = ProtoField.uint32("ncsi.slc.sp1000", "enable 1000 Mbps(1Gbps)", base.DEC, e1_d0, 0x8)
local speed_10g     = ProtoField.uint32("ncsi.slc.sp10g", "enable 10 Gbps", base.DEC, e1_d0, 0x10)

local duplex_half   = ProtoField.uint32("ncsi.slc.duplex", "half-duplex", base.DEC, e1_d0, 0x100)
local duplex_full   = ProtoField.uint32("ncsi.slc.duplex", "full-duplex", base.DEC, e1_d0, 0x200)
local pause_cap     = ProtoField.uint32("ncsi.slc.pause", "Pause Capability", base.DEC, e0_d1, 0x400)
local asy_pause_cap = ProtoField.uint32("ncsi.slc.asy_pause", "Asymmetric Pause Capability", base.DEC, e1_d0, 0x800)
local oem_valid     = ProtoField.uint32("ncsi.slc.oem_valid", "OEM Link Settings Field Valid", base.DEC, e1_d0, 0x1000)

--local link_setting  = ProtoField.uint32("ncsi.slc.link", "Link Settings", base.HEX)
local oem_setting   = ProtoField.uint32("ncsi.slc.oem", "OEM Link Settings", base.HEX)

ncsi_slc.fields = {
    auto_nego, speed_10, speed_100, speed_1000, speed_10g, duplex_half, duplex_full, pause_cap, asy_pause_cap, oem_valid,
    oem_setting
}

local function dissect_set_link_settings(tvbuf, pktinfo, tree)
  tree:add(auto_nego, tvbuf(0, 4))
  tree:add(speed_10, tvbuf(0, 4))
  tree:add(speed_100, tvbuf(0, 4))
  tree:add(speed_1000, tvbuf(0, 4))
  tree:add(speed_10g, tvbuf(0, 4))
  tree:add(duplex_half, tvbuf(0, 4))
  tree:add(duplex_full, tvbuf(0, 4))
  tree:add(pause_cap, tvbuf(0, 4))
  tree:add(asy_pause_cap, tvbuf(0, 4))
  tree:add(oem_valid, tvbuf(0, 4))
  tree:add(oem_setting, tvbuf(0, 4))
end

function ncsi_slc.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
    -- add link status tree iterm
  local link_setting = tree:add(ncsi_slc, tvbuf(0, 4), "Link Settings")
  -- dissect link status
  dissect_set_link_settings(tvbuf, pktinfo, link_setting)
  
  tree:add(oem_setting, tvbuf(4, 4))
  local checksum = tvbuf(8, 4):uint()
  tree:add(tvbuf(8, 4), "Checksum: "..string.format("0x%08x", checksum))
end

payload_dissectors:add(0x09, ncsi_slc)




---------------------------------------------------------------------------------------------
-- Dissector for Set Link Response (0x89)

local setlink_reasons = {
    [0x1] = "Set Link Host OS/ Driver Conflict",
    [0x2] = "Set Link Media Conflict",
    [0x3] = "Set Link Parameter Conflict",
    [0x4] = "Set Link Power Mode Conflict",
    [0x5] = "Set Link Speed Conflict",
    [0x6] = "Link Command Failed-Hardware Access Error"
}

ncsi_slr  = Proto("NC-SI-SLR", pkt_types[0x89])

function ncsi_slr.dissector(tvbuf, pktinfo, tree)
  dissect_resp_reason_code(tvbuf, pktinfo, tree, 0x09, setlink_reasons)
  local checksum = tvbuf(4, 4):uint()
  tree:add(tvbuf(4, 4), "Checksum: "..string.format("0x%08x", checksum))
end

payload_dissectors:add(0x89, ncsi_slr)



---------------------------------------------------------------------------------------------
-- Dissector for Get Link Status Command (0x0A)

ncsi_glsc = Proto("NC-SI-GLSC", pkt_types[0x0A])

function ncsi_glsc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x0A, ncsi_glsc)


---------------------------------------------------------------------------------------------
-- Dissector for Get Link Status Response (0x8A)

ncsi_glsr = Proto("NC-SI-GLSR", pkt_types[0x8A])
-- Table 47 – Link Status Field Bit Definitions

local getlink_reasons = {
  [0x6] = "Link Command Failed-Hardware Access Error"
}

local link_status = ProtoField.uint32("ncsi.glsr.link_status", "Link Status", base.HEX)

local status = {
    [0] = "Link is down",
    [1] = "Link is up"
}
local link_flag   = ProtoField.uint32("ncsi.glsr.link_flag", "Link Flag", base.DEC, status, 0x1)
local speed_and_duplex = {
    [0x0] = "Auto-negotiate not complete/SerDes Flag = 1b/No valid option found(see Spec)",
    [0x1] = "10BASE-T half-duplex",
    [0x2] = "10BASE-T full-duplex",
    [0x3] = "100BASE-TX half-duplex",
    [0x4] = "100BASE-T4",
    [0x5] = "100BASE-TX full-duplex",
    [0x6] = "1000BASE-T half-duplex",
    [0x7] = "1000BASE-T full-duplex",
    [0x8] = "10G-BASE-T support"
}
local speed_duplex        = ProtoField.uint32("ncsi.glsr.speed_duplex", "Speed and duplex", base.HEX, speed_and_duplex, 0x1E)
local auto_nego           = ProtoField.uint32("ncsi.glsr.auto_negi", "Auto Negotiate Flag", base.DEC, e1_d0, 0x20)
local auto_nego_complete  = ProtoField.uint32("ncsi.glsr.auto_negi_complete", "Auto Negotiate Complete", base.DEC, y1_n0, 0x40)
local parallel_detect     = ProtoField.uint32("ncsi.glsr.parallel_detect", "Parallel Detection Flag", base.DEC, y1_n0, 0x80)
-- local reserved           
local cap_1000TFD         = ProtoField.uint32("ncsi.glsr.cap_1000TFD", "Link Partner is 1000BASE-T full-duplex capable", base.DEC, y1_n0, 0x200)
local cap_1000THD         = ProtoField.uint32("ncsi.glsr.cap_1000THD", "Link Partner is 1000BASE-T half-duplex capable", base.DEC, y1_n0, 0x400)
local cap_100T4           = ProtoField.uint32("ncsi.glsr.cap_100T4", "Link Partner is 100BASE-T4 capable", base.DEC, y1_n0, 0x800)
local cap_100TXFD         = ProtoField.uint32("ncsi.glsr.cap_100TXFD", "Link Partner is 100BASE-TX full-duplex capable", base.DEC, y1_n0, 0x1000)
local cap_100TXHD         = ProtoField.uint32("ncsi.glsr.cap_100TXHD", "Link Partner is 100BASE-TX half-duplex capable", base.DEC, y1_n0, 0x2000)
local cap_10TFD           = ProtoField.uint32("ncsi.glsr.cap_10TFD", "Link Partner is 10BASE-T full-duplex capable", base.DEC, y1_n0, 0x4000)
local cap_10THD           = ProtoField.uint32("ncsi.glsr.cap_10THD", "Link Partner is 10BASE-T half-duplex capable", base.DEC, y1_n0, 0x8000)
local tx_flow_ctr         = ProtoField.uint32("ncsi.glsr.tx_flow_ctr", "TX Flow Control Flag", base.DEC, e1_d0, 0x10000) 
local rx_flow_ctr         = ProtoField.uint32("ncsi.glsr.rx_flow_ctr", "RX Flow Control Flag", base.DEC, e1_d0, 0x20000)
local lpa_flow_ctrs = {
    [0x0] = "Link partner is not pause capable",
    [0x1] = "Link partner supports symmetric pause",
    [0x2] = "Link partner supports asymmetric pause toward link partner",
    [0x3] = "Link partner supports both symmetric and asymmetric pause"
}
local lpa_flow_ctr        = ProtoField.uint32("ncsi.glsr.lpa_flow_ctr", "Link Partner Advertised Flow Control", base.HEX, lpa_flow_ctrs, 0xC0000)
local serdes = {
    [0] = "SerDes not used",
    [1] = "SerDes used"
}
local serdes_status       = ProtoField.uint32("ncsi.glsr.serdes_status", "SerDes Link Status", base.DEC, serdes, 0x100000)
local oem_link            = ProtoField.uint32("ncsi.glsr.oem_link", "OEM Link Speed Settings Valid", base.DEC, v1_i0, 0x200000)

-- Table 48 – Other Indications Field Bit Definitions
local host_status = {
    [0] = "Not operational",
    [1] = "Operational"
}
local host_drive_status   = ProtoField.uint32("ncsi.glsr.host_drive_status", "Host NC Driver Status Indication", base.DEC, host_status, 0x1)

-- Table 49 – OEM Link Status Field Bit Definitions (Optional)
local oem_link_status     = ProtoField.uint32("ncsi.glsr.oem_link_status", "OEM Link Status", base.HEX)

ncsi_glsr.fields = {
    -- Table 47 – Link Status Field Bit Definitions
    link_status, link_flag, speed_duplex, auto_nego, auto_nego_complete, parallel_detect, 
    cap_1000TFD, cap_1000THD, cap_100T4, cap_100TXFD, cap_100TXHD, cap_10TFD, cap_10THD,
    tx_flow_ctr, rx_flow_ctr, lpa_flow_ctr, serdes_status, oem_link, 
    -- Table 48 – Other Indications Field Bit Definitions
    host_drive_status, oem_link_status
}

local function dissect_link_status(tvbuf, pktinfo, tree)
  tree:add(link_flag, tvbuf(0, 4))
  tree:add(speed_duplex, tvbuf(0, 4))
  tree:add(auto_nego, tvbuf(0, 4))
  tree:add(auto_nego_complete, tvbuf(0, 4))
  tree:add(parallel_detect, tvbuf(0, 4))
  tree:add(cap_1000TFD, tvbuf(0, 4))
  tree:add(cap_1000THD, tvbuf(0, 4))
  tree:add(cap_100T4, tvbuf(0, 4))
  tree:add(cap_100TXFD, tvbuf(0, 4))
  tree:add(cap_100TXHD, tvbuf(0, 4))
  tree:add(cap_10TFD, tvbuf(0, 4))
  tree:add(cap_10THD, tvbuf(0, 4))
  tree:add(tx_flow_ctr, tvbuf(0, 4))
  tree:add(rx_flow_ctr, tvbuf(0, 4))
  tree:add(lpa_flow_ctr, tvbuf(0, 4))
  tree:add(serdes_status, tvbuf(0, 4))
  tree:add(oem_link, tvbuf(0, 4))
end

local function dissect_other_indications(tvbuf, pktinfo, tree)
  tree:add(host_drive_status, tvbuf(0, 4))
end

function ncsi_glsr.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  -- response code and reason code
  dissect_resp_reason_code(tvbuf, pktinfo, tree, 0x0A, getlink_reasons)
  
  -- add link status tree iterm
  local link_status_tree = tree:add(link_status, tvbuf(4, 4))
  -- dissect link status
  dissect_link_status(tvbuf(4, 4):tvb(), pktinfo, link_status_tree)
  -- add other indications tree item
  local other_indication = tree:add(ncsi_glsr, tvbuf(8, 4), "Other Indications")
  -- dissect other indications
  dissect_other_indications(tvbuf(8, 4):tvb(), pktinfo, other_indication)
  -- add OEM link status
  tree:add(oem_link_status, tvbuf(12, 4))
  -- add checksum
  local checksum = tvbuf(16, 4):uint()
  tree:add(tvbuf(20, 4), "Checksum: "..string.format("0x%08x", checksum))
end 

payload_dissectors:add(0x8A, ncsi_glsr)



---------------------------------------------------------------------------------------------
-- Dissector for Set VLAN Filter Command (0x0B)

ncsi_svfc = Proto("NC-SI-SVFC", pkt_types[0x0B])

local vlan        = ProtoField.ubytes("ncsi.svfc.vlan", "User Priority/DEI and VLAN ID", base.SPACE)
local filter      = ProtoField.uint8("ncsi.svfc.filter", "Filter Selector", base.HEX)
local vlan_enable = ProtoField.bool("ncsi.svfc.enable", "Enable this VLAN filter", 8, nil, 0x1)

ncsi_svfc.fields = {
    vlan, filter, vlan_enable
}

function ncsi_svfc.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  tree:add(vlan, tvbuf(2, 2))
  tree:add(filter, tvbuf(6, 1))
  tree:add(vlan_enable, tvbuf(7, 1))
  local checksum = tvbuf(8, 4):uint()
  tree:add(tvbuf(8, 4), "Checksum: "..string.format("0x%08x", checksum))
end

payload_dissectors:add(0x0B, ncsi_svfc)



---------------------------------------------------------------------------------------------
-- Dissector for Set VLAN Filter Response (0x8B)

ncsi_svfr  = Proto("NC-SI-SVFR", pkt_types[0x8B])

local setvlan_reasons = {
    [0x7] = "VLAN Tag Is Invalid"
}

function ncsi_svfr.dissector(tvbuf, pktinfo, tree)
  dissect_resp_reason_code(tvbuf, pktinfo, tree, 0x0B, setvlan_reasons)
  local checksum = tvbuf(4, 4):uint()
  tree:add(tvbuf(4, 4), "Checksum: "..string.format("0x%08x", checksum))
end

payload_dissectors:add(0x8B, ncsi_svfr)




---------------------------------------------------------------------------------------------
-- Dissector for Enable VLAN Command (0x0C)

ncsi_evc  = Proto("NC-SI-EVC", pkt_types[0x0C])

vlan_modes = {
    [0x00]  = "Reserved",
    [0x01]  = "VLAN only",
    [0x02]  = "VLAN + non-VLAN",
    [0x03]  = "Any VLAN + non-VLAN"
}
local vlan_mode = ProtoField.uint8("ncsi.evc.mode", "VLAN Enable Modes", base.HEX, vlan_modes)

ncsi_evc.fields = {
    vlan_mode
}

function ncsi_evc.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  tree:add(vlan_mode, tvbuf(3, 1))
  common_dissector(tvbuf(4, 4):tvb(), pktinfo, tree)
end

payload_dissectors:add(0x0C, ncsi_evc)





---------------------------------------------------------------------------------------------
-- Dissector for Enable VLAN Response (0x8C)

ncsi_evr  = Proto("NC-SI-EVR", pkt_types[0x8C])

function ncsi_evr.dissector(tvbuf, pktinfo, tree)
  rep_common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x8C, ncsi_evr)




---------------------------------------------------------------------------------------------
-- Dissector for Disable VLAN Command (0x0D)

ncsi_dvc  = Proto("NC-SI-DVC", pkt_types[0x0D])

function ncsi_dvc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x0D, ncsi_dvc)



---------------------------------------------------------------------------------------------
-- Dissector for Disable VLAN Response (0x8D)

ncsi_dvr  = Proto("NC-SI-DVR", pkt_types[0x8D])

function ncsi_dvr.dissector(tvbuf, pktinfo, tree)
  rep_common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x8D, ncsi_dvr)



---------------------------------------------------------------------------------------------
-- Dissector for Set MAC Address Command (0x0E)

ncsi_smac = Proto("NC-SI-SMAC", "Set MAC Address Command (0x0E)")

local mac_addr  = ProtoField.ether("ncsi.smac.mac", "MAC Address")
local mac_num   = ProtoField.uint8("ncsi.smac.num", "MAC address filter number", base.DEC)
local addr_types = {
    [0x0] = "Unicast MAC address",
    [0x1] = "Multicast MAC address"
}
local addr_type = ProtoField.uint8("ncsi.smac.at", "Address Type", base.HEX, addr_types, 0xE0)
local filer_flags = {
    [0] = "Disable this MAC address filter",
    [1] = "Enable this MAC address filter"
}
local filter_e  = ProtoField.uint8("ncsi.smac.filter", "MAC address filter enable", base.DEC, filer_flags, 0x1)

ncsi_smac.fields = {
    mac_addr, mac_num, addr_type, filter_e
}

function ncsi_smac.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  tree:add(mac_addr, tvbuf(0, 6))
  tree:add(mac_num, tvbuf(6, 1))
  tree:add(addr_type, tvbuf(7, 1))
  tree:add(filter_e, tvbuf(7, 1))
  local checksum = tvbuf(8, 4):uint()
  tree:add(tvbuf(8, 4), "Checksum: "..string.format("0x%08x", checksum))
end

payload_dissectors:add(0x0E, ncsi_smac)





---------------------------------------------------------------------------------------------
-- Dissector for Set MAC Address Response (0x8E)

ncsi_smar  = Proto("NC-SI-SMAR", pkt_types[0x8E])

local setmac_reasons = {
    [0x8] = "MAC Address Is Zero"
}

function ncsi_smar.dissector(tvbuf, pktinfo, tree)
  dissect_resp_reason_code(tvbuf, pktinfo, tree, 0x0E, setmac_reasons)
  local checksum = tvbuf(4, 4):uint()
  tree:add(tvbuf(4, 4), "Checksum: "..string.format("0x%08x", checksum))
end

payload_dissectors:add(0x8E, ncsi_smar)




---------------------------------------------------------------------------------------------
-- Dissector for Enable Broadcast Filter Command (0x10)

ncsi_ebfc = Proto("NC-SI-EBFC", pkt_types[0x10])

local filters   = ProtoField.uint32("ncsi.ebfc.filter", "Broadcast Packet Filter Settings", base.HEX)
local filter_values = {
    [0] = "Filter out this packet type",
    [1] = "Forward this packet type to the Management Controller"
}
local arp       = ProtoField.uint32("ncsi.ebfc.arp", "ARP Packets", base.HEX, filter_values, 0x1)
local dhcp_c    = ProtoField.uint32("ncsi.ebfc.dhcp_c", "DHCP Client Packets", base.HEX, filter_values, 0x2)
local dhcp_s    = ProtoField.uint32("ncsi.ebfc.dhcp_s", "DHCP Server Packets", base.HEX, filter_values, 0x4)
local netbios   = ProtoField.uint32("ncsi.ebfc.netbios", "NetBIOS Packets", base.HEX, filter_values, 0x8)
 
ncsi_ebfc.fields = {
    filters, arp, dhcp_c, dhcp_s, netbios
}

function ncsi_ebfc.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  local filter_tree = tree:add(filters, tvbuf(0, 4))
  filter_tree:add(arp, tvbuf(0, 4))
  filter_tree:add(dhcp_c, tvbuf(0, 4))
  filter_tree:add(dhcp_s, tvbuf(0, 4))
  filter_tree:add(netbios, tvbuf(0, 4))
  local checksum = tvbuf(4, 4):uint()
  tree:add(tvbuf(4, 4), "Checksum: "..string.format("0x%08x", checksum))
end

payload_dissectors:add(0x10, ncsi_ebfc)





---------------------------------------------------------------------------------------------
-- Dissector for Enable Broadcast Filter Response (0x90)

ncsi_ebfr  = Proto("NC-SI-EBFR", pkt_types[0x90])

function ncsi_ebfr.dissector(tvbuf, pktinfo, tree)
  rep_common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x90, ncsi_ebfr)





---------------------------------------------------------------------------------------------
-- Dissector for Disable Broadcast Filter Command (0x11)

ncsi_dbfc  = Proto("NC-SI-DBFC", pkt_types[0x11])

function ncsi_dbfc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x11, ncsi_dbfc)


---------------------------------------------------------------------------------------------
-- Dissector for Disable Broadcast Filter Response (0x91)

ncsi_dbfr  = Proto("NC-SI-DBFR", pkt_types[0x91])

function ncsi_dbfr.dissector(tvbuf, pktinfo, tree)
  rep_common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x91, ncsi_dbfr)




---------------------------------------------------------------------------------------------
-- Dissector for Enable Global Multicast Filter Command (0x12)

ncsi_egmfc = Proto("NC-SI-EGFC", pkt_types[0x12])

local filters   = ProtoField.uint32("ncsi.egmfc.filter", "Multicast Packet Filter Settings", base.HEX)
local filter_values = {
    [0] = "Filter out this packet type",
    [1] = "Forward this packet type to the Management Controller"
}
local neighbor  = ProtoField.uint32("ncsi.egmfc.neighbor", "IPv6 Neighbor Advertisement", base.HEX, filter_values, 0x1)
local router    = ProtoField.uint32("ncsi.egmfc.rounter", "IPv6 Router Advertisement", base.HEX, filter_values, 0x2)
local dhcpv6    = ProtoField.uint32("ncsi.egmfc.dhcpv6", "DHCPv6 relay and server multicast", base.HEX, filter_values, 0x4)
 
ncsi_egmfc.fields = {
    filters, neighbor, router, dhcpv6
}

function ncsi_egmfc.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  local filter_tree = tree:add(filters, tvbuf(0, 4))
  filter_tree:add(neighbor, tvbuf(0, 4))
  filter_tree:add(router, tvbuf(0, 4))
  filter_tree:add(dhcpv6, tvbuf(0, 4))
  local checksum = tvbuf(4, 4):uint()
  tree:add(tvbuf(4, 4), "Checksum: "..string.format("0x%08x", checksum))
end

payload_dissectors:add(0x12, ncsi_egmfc)




---------------------------------------------------------------------------------------------
-- Dissector for Enable Global Multicast Filter Response (0x92)

ncsi_egmfr  = Proto("NC-SI-EGMFR", pkt_types[0x92])

function ncsi_egmfr.dissector(tvbuf, pktinfo, tree)
  rep_common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x92, ncsi_egmfr)


---------------------------------------------------------------------------------------------
-- Dissector for Disable Global Multicast Filter Command (0x13)

ncsi_dgmfc  = Proto("NC-SI-DGMFC", pkt_types[0x13])

function ncsi_dgmfc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x13, ncsi_dgmfc)



---------------------------------------------------------------------------------------------
-- Dissector for Disable Global Multicast Filter Response (0x93)

ncsi_dgmfr  = Proto("NC-SI-DGMFR", pkt_types[0x93])

function ncsi_dgmfr.dissector(tvbuf, pktinfo, tree)
  rep_common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x93, ncsi_dgmfr)




---------------------------------------------------------------------------------------------
-- Dissector for Set NC-SI Flow Control Command (0x14)

ncsi_sfcc   = Proto("NC-SI-SFCC", pkt_types[0x14])

flow_ctrls = {
    [0] = "Disables NC-SI flow control",
    [1] = "Enables NC to MC flow control frames (NC generates flow control frames)",
    [2] = "Enables MC to NC flow control frames (NC accepts flow control frames)",
    [3] = "Enables bi-directional flow control frames"
}

local flow_ctrl   = ProtoField.uint8("ncsi.sfcc.flctrl", "Flow Control Enable Field", base.HEX, flow_ctrls)

ncsi_sfcc.fields = {
    flow_ctrl
}

function ncsi_sfcc.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  tree:add(flow_ctrl, tvbuf(3, 1))
  common_dissector(tvbuf(4, 4):tvb(), pktinfo, tree)
end

payload_dissectors:add(0x14, ncsi_sfcc)



---------------------------------------------------------------------------------------------
-- Dissector for Set NC-SI Flow Control Response (0x94)

ncsi_sfcr  = Proto("NC-SI-SFCR", pkt_types[0x94])

local set_flctr_reasons = {
  [0x9] = "Independent transmit and receive enable/disable control is not supported"
}

function ncsi_sfcr.dissector(tvbuf, pktinfo, tree)
  dissect_resp_reason_code(tvbuf, pktinfo, tree, 0x14, set_flctr_reasons)
  local checksum = tvbuf(4, 4):uint()
  tree:add(tvbuf(4, 4), "Checksum: "..string.format("0x%08x", checksum))
end

payload_dissectors:add(0x94, ncsi_sfcr)



---------------------------------------------------------------------------------------------
-- Dissector for Get Version ID Command (0x15)

ncsi_gvidc  = Proto("NC-SI-GVIDC", pkt_types[0x15])

function ncsi_gvidc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x15, ncsi_gvidc)





---------------------------------------------------------------------------------------------
-- Dissector for Get Version ID Response (0x95)

ncsi_gvidr  = Proto("NC-SI-GVIDR", "Get Version ID Response (0x95)")

local ncsi_ver    = ProtoField.uint32("ncsi.gvidr.ver", "NC-SI Version", base.HEX)
local major       = ProtoField.uint8("ncsi.gvidr.major", "Major", base.HEX)
local minor       = ProtoField.uint8("ncsi.gvidr.minor", "Minor", base.HEX)
local update      = ProtoField.uint8("ncsi.gvidr.update", "Update", base.HEX)
local alpha1      = ProtoField.uint8("ncsi.gvidr.alpha1", "Alpha1", base.HEX)
local alpha2      = ProtoField.uint8("ncsi.gvidr.alpha2", "Alpha2", base.HEX)
local fw_name     = ProtoField.string("ncsi.gvidr.fw", "Firmware Name", base.ASCII)
local fw_ver      = ProtoField.uint32("ncsi.gvidr.fm_ver", "Firmware Version", base.HEX)
local ms_byte     = ProtoField.uint8("ncsi.gvidr.msb", "MS-byte (3)", base.HEX)
local byte2       = ProtoField.uint8("ncsi.gvidr.b2", "Byte (2)", base.HEX)
local byte1       = ProtoField.uint8("ncsi.gvidr.b1", "Byte (1)", base.HEX)
local ls_byte     = ProtoField.uint8("ncsi.gvidr.lsb", "LS-byte (0)", base.HEX)

local pci_did     = ProtoField.uint16("ncsi.gvidr.did", "PCI DID", base.HEX)
local pci_vid     = ProtoField.uint16("ncsi.gvidr.vid", "PCI VID", base.HEX)
local pci_ssid    = ProtoField.uint16("ncsi.gvidr.ssid", "PCI SSID", base.HEX)
local pci_svid    = ProtoField.uint16("ncsi.gvidr.svid", "PCI SVID", base.HEX)

local iana        = ProtoField.uint32("ncsi.gvidr.iana", "Manufacturer ID (IANA)", base.HEX)

ncsi_gvidr.fields = {
    ncsi_ver, major, minor, update, alpha1, alpha2, 
    fw_name, fw_ver, ms_byte, byte2, byte1, ls_byte,
    pci_did, pci_vid, pci_ssid, pci_svid, iana
}

function ncsi_gvidr.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  -- Response code and Reason code
  dissect_resp_reason_code(tvbuf, pktinfo, tree)
  local ver_tree = tree:add(ncsi_ver, tvbuf(4, 4))
  ver_tree:add(major, tvbuf(4, 1))
  ver_tree:add(minor, tvbuf(5, 1))
  ver_tree:add(update, tvbuf(6, 1))
  ver_tree:add(alpha1, tvbuf(7, 1))
  tree:add(alpha2, tvbuf(11, 1))
  tree:add(fw_name, tvbuf(12, 12))
  
  local fw_ver_tree = tree:add(fw_ver, tvbuf(24, 4))
  fw_ver_tree:add(ms_byte, tvbuf(24, 1))
  fw_ver_tree:add(byte2, tvbuf(25, 1))
  fw_ver_tree:add(byte1, tvbuf(26, 1))
  fw_ver_tree:add(ls_byte, tvbuf(27, 1))
  
  tree:add(pci_did, tvbuf(28, 2))
  tree:add(pci_vid, tvbuf(30, 2))
  tree:add(pci_ssid, tvbuf(32, 2))
  tree:add(pci_svid, tvbuf(34, 2))
  tree:add(iana, tvbuf(36, 4))
  
  local checksum = tvbuf(40, 4):uint()
  tree:add(tvbuf(40, 4), "Checksum: "..string.format("0x%08x", checksum))
end

payload_dissectors:add(0x95, ncsi_gvidr)





---------------------------------------------------------------------------------------------
-- Dissector for Get Capabilities Command (0x16)

ncsi_gcc  = Proto("NC-SI-GCC", pkt_types[0x16])

function ncsi_gcc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x16, ncsi_gcc)





---------------------------------------------------------------------------------------------
-- Dissector for Get Capabilities Response (0x96)

ncsi_gcr  = Proto("NC-SI-GCR", "Get Capabilities Response (0x96)")

local cap_flags = ProtoField.uint32("ncsi.gcr.cap_flags", "Capabilities Flags", base.HEX)
local s1_n0 = {
    [0] = "not supported",
    [1] = "supported"
}
local hw_arb    = ProtoField.uint32("ncsi.gcr.hw_arb", "Hardware Arbitration", base.DEC, s1_n0, 0x1)
local nc_drv    = ProtoField.uint32("ncsi.gcr.nc_drv", "Host NC Driver Status", base.DEC, s1_n0, 0x2)
local nc2mc     = ProtoField.uint32("ncsi.gcr.nc2mc", "NC to MC flow control", base.DEC, s1_n0, 0x4)
local mc2nc     = ProtoField.uint32("ncsi.gcr.mc2nc", "MC to NC flow control", base.DEC, s1_n0, 0x8)
local multiaddr = ProtoField.uint32("ncsi.gcr.multiaddr", "All multicast addresses support", base.DEC, s1_n0, 0x10)

local bp_filter_cap   = ProtoField.uint32("ncsi.gcr.filter", "Broadcast Packet Filter Settings", base.HEX)

local arp       = ProtoField.uint32("ncsi.gcr.arp", "ARP Packets filter", base.HEX, s1_n0, 0x1)
local dhcp_c    = ProtoField.uint32("ncsi.gcr.dhcp_c", "DHCP Client Packets filter", base.HEX, s1_n0, 0x2)
local dhcp_s    = ProtoField.uint32("ncsi.gcr.dhcp_s", "DHCP Server Packets filter", base.HEX, s1_n0, 0x4)
local netbios   = ProtoField.uint32("ncsi.gcr.netbios", "NetBIOS Packets filter", base.HEX, s1_n0, 0x8)

local mp_filter_cap   = ProtoField.uint32("ncsi.gcr.filter", "Broadcast Packet Filter Settings", base.HEX)

local neighbor  = ProtoField.uint32("ncsi.gcr.neighbor", "IPv6 Neighbor Advertisement filter", base.HEX, s1_n0, 0x1)
local router    = ProtoField.uint32("ncsi.gcr.rounter", "IPv6 Router Advertisement filter", base.HEX, s1_n0, 0x2)
local dhcpv6    = ProtoField.uint32("ncsi.gcr.dhcpv6", "DHCPv6 relay and server multicast filter", base.HEX, s1_n0, 0x4)

local buf_cap   = ProtoField.uint32("ncsi.gcr.buf", "Buffering Capability", base.HEX)

local aen_ctrl      = ProtoField.uint32("ncsi.gcr.aen_ctrl", "AEN Control", base.HEX)

local lsc_aen_ctrl  = ProtoField.uint32("ncsi.gcr.lsc", "Link Status Change AEN control", base.DEC, s1_n0, 0x1)
local cr_aen_ctrl   = ProtoField.uint32("ncsi.gcr.cr", "Configuration Required AEN control", base.DEC, s1_n0, 0x2)
local hsc_aen_ctrl  = ProtoField.uint32("ncsi.gcr.hsc", "Host NC Driver Status Change AEN control", base.DEC, s1_n0, 0x4)
local reserved      = ProtoField.uint32("ncsi.gcr.rsvd", "Reserved", base.DEC, nil, 0xFFF8)
local oem_aen_ctrl  = ProtoField.uint32("ncsi.gcr.oem", "OEM-specific AEN control", base.DEC, nil, 0xFFFF0000)

local vlan_count    = ProtoField.uint8("ncsi.gcr.vlan", "VLAN Filter Count", base.HEX)
local mixd_count    = ProtoField.uint8("ncsi.gcr.mixd", "Mixed Filter Count", base.HEX)
local multi_count   = ProtoField.uint8("ncsi.gcr.nulti", "Multicast Filter Count", base.HEX)
local uni_count     = ProtoField.uint8("ncsi.gcr.uni", "Unicast Filter Count", base.HEX)

local vlan_mode     = ProtoField.uint8("ncsi.gcr.vlan_mode", "VLAN Mode Support", base.HEX)
local vlan_bit0     = ProtoField.uint8("ncsi.gcr.vlan_bit0", "Filtering VLAN only", base.DEC, s1_n0, 0x1)
local vlan_bit1     = ProtoField.uint8("ncsi.gcr.vlan_bit1", "Filtering ‘VLAN + non-VLAN’ traffic", base.DEC, s1_n0, 0x2)
local vlan_bit2     = ProtoField.uint8("ncsi.gcr.vlan_bit2", "Filtering ‘Any VLAN + non-VLAN’ traffic", base.DEC, s1_n0, 0x4)

local cn_count      = ProtoField.uint8("ncsi.gcr.cn_count", "Channel Count", base.HEX)

ncsi_gcr.fields = {
    cap_flags, hw_arb, nc_drv, nc2mc, mc2nc, multiaddr,
    bp_filter_cap, arp, dhcp_c, dhcp_s, netbios,
    mp_filter_cap, neighbor, router, dhcpv6,
    buf_cap, aen_ctrl, lsc_aen_ctrl, cr_aen_ctrl, hsc_aen_ctrl, reserved, oem_aen_ctrl,
    vlan_count, mixd_count, multi_count, uni_count,
    vlan_mode, vlan_bit0, vlan_bit1, vlan_bit2, cn_count
}


function ncsi_gcr.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  dissect_resp_reason_code(tvbuf, pktinfo, tree)
  
  local cap_flags_tree = tree:add(cap_flags, tvbuf(4, 4))
  cap_flags_tree:add(hw_arb, tvbuf(4, 4))
  cap_flags_tree:add(nc_drv, tvbuf(4, 4))
  cap_flags_tree:add(nc2mc, tvbuf(4, 4))
  cap_flags_tree:add(mc2nc, tvbuf(4, 4))
  cap_flags_tree:add(multiaddr, tvbuf(4, 4))
  
  local bp_filter_cap_tree = tree:add(bp_filter_cap, tvbuf(8, 4))
  bp_filter_cap_tree:add(arp, tvbuf(8, 4))
  bp_filter_cap_tree:add(dhcp_c, tvbuf(8, 4))
  bp_filter_cap_tree:add(dhcp_s, tvbuf(8, 4))
  bp_filter_cap_tree:add(netbios, tvbuf(8, 4))
  
  local mp_filter_cap_tree = tree:add(mp_filter_cap, tvbuf(12, 4))
  mp_filter_cap_tree:add(neighbor, tvbuf(12, 4))
  mp_filter_cap_tree:add(router, tvbuf(12, 4))
  mp_filter_cap_tree:add(dhcpv6, tvbuf(12, 4))
  
  tree:add(buf_cap, tvbuf(16, 4))
  
  local aen_ctrl_tree = tree:add(aen_ctrl, tvbuf(20, 4))
  aen_ctrl_tree:add(lsc_aen_ctrl, tvbuf(20, 4))
  aen_ctrl_tree:add(cr_aen_ctrl, tvbuf(20, 4))
  aen_ctrl_tree:add(hsc_aen_ctrl, tvbuf(20, 4))
  aen_ctrl_tree:add(reserved, tvbuf(20, 4))
  aen_ctrl_tree:add(oem_aen_ctrl, tvbuf(20, 4))
  
  tree:add(vlan_count, tvbuf(24, 1))
  tree:add(mixd_count, tvbuf(25, 1))
  tree:add(multi_count, tvbuf(26, 1))
  tree:add(uni_count, tvbuf(27, 1))
  
  local vlan_mode_tree = tree:add(vlan_mode, tvbuf(30, 1))
  vlan_mode_tree:add(vlan_bit0, tvbuf(30, 1))
  vlan_mode_tree:add(vlan_bit1, tvbuf(30, 1))
  vlan_mode_tree:add(vlan_bit2, tvbuf(30, 1))
  
  tree:add(cn_count, tvbuf(31, 1))
  
  local checksum = tvbuf(32, 4):uint()
  tree:add(tvbuf(32, 4), "Checksum: "..string.format("0x%08x", checksum))
end

payload_dissectors:add(0x96, ncsi_gcr)



---------------------------------------------------------------------------------------------
-- Dissector for Get Parameters Command (0x17)

ncsi_gpc  = Proto("NC-SI-GPC", pkt_types[0x17])

function ncsi_gpc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x17, ncsi_gpc)



---------------------------------------------------------------------------------------------
-- Dissector for Get Parameters Response (0x97)

ncsi_gpr  = Proto("NC-SI-GPR", "Get Parameters Response (0x97)")
local mac_count    = ProtoField.uint8("ncsi.gpr.mac_count", "MAC Adress Count", base.DEC)
local mac_flags    = ProtoField.uint8("ncsi.gpr.mac_flags", "MAC Adress Flags", base.HEX)
-- add details
local flag_defs = {
    [0] = "Default or unsupported or disabled",
    [1] = "Enabled"
}

local mac_bits = {
  [0] = ProtoField.uint8("ncsi.gpr.mac_bit0", "MAC address 1 status", base.DEC, flag_defs, 0x01),
  [1] = ProtoField.uint8("ncsi.gpr.mac_bit1", "MAC address 2 status", base.DEC, flag_defs, 0x02),
  [2] = ProtoField.uint8("ncsi.gpr.mac_bit2", "MAC address 3 status", base.DEC, flag_defs, 0x04),
  [3] = ProtoField.uint8("ncsi.gpr.mac_bit3", "MAC address 4 status", base.DEC, flag_defs, 0x08),
  [4] = ProtoField.uint8("ncsi.gpr.mac_bit4", "MAC address 5 status", base.DEC, flag_defs, 0x10),
  [5] = ProtoField.uint8("ncsi.gpr.mac_bit5", "MAC address 6 status", base.DEC, flag_defs, 0x20),
  [6] = ProtoField.uint8("ncsi.gpr.mac_bit6", "MAC address 7 status", base.DEC, flag_defs, 0x40),
  [7] = ProtoField.uint8("ncsi.gpr.mac_bit7", "MAC address 8 status", base.DEC, flag_defs, 0x80),
}

local vlan_count   = ProtoField.uint8("ncsi.gpr.vlan_count", "VLAN Tag Count", base.DEC)
local vlan_flags   = ProtoField.uint16("ncsi.gpr.vlan_flags", "VLAN Tag Flags", base.HEX)
-- add details
local vlan_bits = {
  [0] = ProtoField.uint16("ncsi.gpr.vlan_bit0", "VLAN Tag 1 status", base.DEC, flag_defs, 0x0001),
  [1] = ProtoField.uint16("ncsi.gpr.vlan_bit1", "VLAN Tag 2 status", base.DEC, flag_defs, 0x0002),
  [2] = ProtoField.uint16("ncsi.gpr.vlan_bit2", "VLAN Tag 3 status", base.DEC, flag_defs, 0x0004),
  [3] = ProtoField.uint16("ncsi.gpr.vlan_bit3", "VLAN Tag 4 status", base.DEC, flag_defs, 0x0008),
  [4] = ProtoField.uint16("ncsi.gpr.vlan_bit4", "VLAN Tag 5 status", base.DEC, flag_defs, 0x0010),
  [5] = ProtoField.uint16("ncsi.gpr.vlan_bit5", "VLAN Tag 6 status", base.DEC, flag_defs, 0x0020),
  [6] = ProtoField.uint16("ncsi.gpr.vlan_bit6", "VLAN Tag 7 status", base.DEC, flag_defs, 0x0040),
  [7] = ProtoField.uint16("ncsi.gpr.vlan_bit7", "VLAN Tag 8 status", base.DEC, flag_defs, 0x0080),
  [8] = ProtoField.uint16("ncsi.gpr.vlan_bit8", "VLAN Tag 9 status", base.DEC, flag_defs, 0x0100),
  [9] = ProtoField.uint16("ncsi.gpr.vlan_bit9", "VLAN Tag 10 status", base.DEC, flag_defs, 0x0200),
  [10] = ProtoField.uint16("ncsi.gpr.vlan_bit10", "VLAN Tag 11 status", base.DEC, flag_defs, 0x0400),
  [11] = ProtoField.uint16("ncsi.gpr.vlan_bit11", "VLAN Tag 12 status", base.DEC, flag_defs, 0x0800),
  [12] = ProtoField.uint16("ncsi.gpr.vlan_bit12", "VLAN Tag 13 status", base.DEC, flag_defs, 0x1000),
  [13] = ProtoField.uint16("ncsi.gpr.vlan_bit13", "VLAN Tag 14 status", base.DEC, flag_defs, 0x2000),
  [14] = ProtoField.uint16("ncsi.gpr.vlan_bit14", "VLAN Tag 15 status", base.DEC, flag_defs, 0x4000),
}

local link_setting  =  ProtoField.uint32("ncsi.gpr.link_settings", "Link Settings", base.HEX)
-- TODO add details

local bpfs          = ProtoField.uint32("ncsi.gpr.bpfs", "Broadcast Packet Filter Settings", base.HEX)
-- TODO add details
local conf_flags    = ProtoField.uint32("ncsi.gpr.conf_flags", "Configuration Flags", base.HEX)
-- add details
local conf_bits = {
  [0] = ProtoField.uint32("ncsi.gpr.conf_bit0", "Broadcast Packet Filter status", base.DEC, e1_d0, 0x00000001),
  [1] = ProtoField.uint32("ncsi.gpr.conf_bit1", "Channel Enabled", base.DEC, e1_d0, 0x00000002),
  [2] = ProtoField.uint32("ncsi.gpr.conf_bit2", "Channel Network TX Enabled", base.DEC, e1_d0, 0x00000004),
  [3] = ProtoField.uint32("ncsi.gpr.conf_bit3", "Global Multicast Packet Filter Status", base.DEC, e1_d0, 0x00000008)
}

local vlan_mode     = ProtoField.uint8("ncsi.gpr.vlan_mode", "VLAN Mode", base.HEX, vlan_modes)
-- TODO add details
local flow_ctrl     = ProtoField.uint8("ncsi.gpr.flow_ctrl", "Flow Control Enable", base.HEX, flow_ctrls)
-- TODO add details
local aen_ctrl      = ProtoField.uint32("ncsi.gpr.aen_ctrl", "AEN Control", base.HEX)
-- TODO add details

local macs = {
  [1] = ProtoField.ether("ncsi.gpr.mac_1", "MAC Address 1"),
  [2] = ProtoField.ether("ncsi.gpr.mac_2", "MAC Address 2"),
  [3] = ProtoField.ether("ncsi.gpr.mac_3", "MAC Address 3"),
  [4] = ProtoField.ether("ncsi.gpr.mac_4", "MAC Address 4"),
  [5] = ProtoField.ether("ncsi.gpr.mac_5", "MAC Address 5"),
  [6] = ProtoField.ether("ncsi.gpr.mac_6", "MAC Address 6"),
  [7] = ProtoField.ether("ncsi.gpr.mac_7", "MAC Address 7"),
  [8] = ProtoField.ether("ncsi.gpr.mac_8", "MAC Address 8")
}


ncsi_gpr.fields = {
    mac_count, mac_flags, mac_bits[0], mac_bits[1], mac_bits[2], mac_bits[3], mac_bits[4], mac_bits[5], mac_bits[6], mac_bits[7],
    vlan_count, vlan_flags, vlan_bits[0], vlan_bits[1], vlan_bits[2], vlan_bits[3], vlan_bits[4], vlan_bits[5], vlan_bits[6], 
    vlan_bits[7], vlan_bits[8], vlan_bits[9], vlan_bits[10], vlan_bits[11], vlan_bits[12], vlan_bits[13], vlan_bits[14],
    link_setting, bpfs, conf_flags, conf_bits[0], conf_bits[1], conf_bits[2], conf_bits[3],
    vlan_mode, flow_ctrl, aen_ctrl,
    macs[1], macs[2], macs[3], macs[4], macs[5], macs[6], macs[7], macs[8]
}


function ncsi_gpr.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  dissect_resp_reason_code(tvbuf, pktinfo, tree)
  
  local mac_num = tvbuf(4, 1):uint()
  tree:add(mac_count, tvbuf(4, 1))
  
  local mac_flag_tree = tree:add(mac_flags, tvbuf(7, 1))
  -- add details
  for i = 0, 7, 1 do
    mac_flag_tree:add(mac_bits[i], tvbuf(7, 1))
  end
  
  local vlan_num = tvbuf(8, 1):uint()
  tree:add(vlan_count, tvbuf(8, 1))
  local vlan_flag_tree = tree:add(vlan_flags, tvbuf(10, 2))
  -- add details
  for i = 0, 14, 1 do
    vlan_flag_tree:add(vlan_bits[i], tvbuf(10, 2))
  end
  
  local link_setting_tree = tree:add(link_setting, tvbuf(12, 4))
  -- add details  
  -- dissect link status  
  dissect_set_link_settings(tvbuf(12, 4):tvb(), pktinfo, link_setting_tree)
  
  
  local bpfs_tree = tree:add(bpfs, tvbuf(16, 4))
  -- TODO add details  
  
  local conf_flags_tree = tree:add(conf_flags, tvbuf(20, 4))
  -- add details
  for i = 0, 3, 1 do
    conf_flags_tree:add(conf_bits[i], tvbuf(20, 4))
  end   
  
  tree:add(vlan_mode, tvbuf(24, 1))
  tree:add(flow_ctrl, tvbuf(25, 1))
  
   local aen_ctrl_tree = tree:add(aen_ctrl, tvbuf(28, 4))
  -- add details   
  dissect_aen_ctrl(tvbuf(28, 4):tvb(), pktinfo, aen_ctrl_tree)
  
  
  local mac_tree = tree:add(tvbuf(32, 6 * mac_num), "MAC Adresses")
  local offset = 32
  for i = 1, mac_num, 1 do
    mac_tree:add(macs[i], tvbuf(offset, 6))
    offset = offset + 6
  end
  
  local vlan_tree = tree:add(tvbuf(offset, 2 * vlan_num), "VLAN Tags")
  for i = 1, vlan_num, 1 do
    local vlan_tag = tvbuf(offset, 2):uint()
    vlan_tree:add(tvbuf(offset, 2), "VLAN Tag "..string.format("%d", i)..": "..string.format("0x%04x", vlan_tag))
    offset = offset + 2
  end
  
  if ((offset % 4) ~= 0) then
    offset = offset + (4 - (offset % 4))
  end
  
  local checksum = tvbuf(offset, 4):uint()
  tree:add(tvbuf(offset, 4), "Checksum: "..string.format("0x%08x", checksum))
end

payload_dissectors:add(0x97, ncsi_gpr)



---------------------------------------------------------------------------------------------
-- Dissector for Get Controller Packet Statistics Command (0x18)

ncsi_gcpsc  = Proto("NC-SI-GCPSC", pkt_types[0x18])

function ncsi_gcpsc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x18, ncsi_gcpsc)




---------------------------------------------------------------------------------------------
-- Dissector for Get Controller Packet Statistics Response (0x98)

ncsi_gcpsr  = Proto("NC-SI-GCPSR", pkt_types[0x98])

local controller_statistics = {
    [0] = "Total Bytes Received",
    [1] = "Total Bytes Transmitted",
    [2] = "Total Unicast Packets Received",
    [3] = "Total Multicast Packets Received",
    [4] = "Total Broadcast Packets Received",
    [5] = "Total Unicast Packets Transmitted",
    [6] = "Total Multicast Packets Transmitted",
    [7] = "Total Broadcast Packets Transmitted",
    [8] = "FCS Receive Errors",
    [9] = "Alignment Errors",
    [10] = "False Carrier Detections",
    [11] = "Runt Packets Received",
    [12] = "Jabber Packets Received",
    [13] = "Pause XON Frames Received",
    [14] = "Pause XOFF Frames Received",
    [15] = "Pause XOFF Frames Transmitted",
    [16] = "Pause XOFF Frames Transmitted",
    [17] = "Single Collision Transmit Frames",
    [18] = "Multiple Collision Transmit Frames",
    [19] = "Late Collision Frames",
    [20] = "Excessive Collision Frames",
    [21] = "Control Frames Received",
    [22] = "64 Byte Frames Received",
    [23] = "65–127 Byte Frames Received",
    [24] = "128–255 Byte Frames Received",
    [25] = "256–511 Byte Frames Received",
    [26] = "512–1023 Byte Frames Received",
    [27] = "1024–1522 Byte Frames Received",
    [28] = "1523–9022 Byte Frames Received",
    [29] = "64 Byte Frames Transmitted",
    [30] = "65–127 Byte Frames Transmitted",
    [31] = "128–255 Byte Frames Transmitted",
    [32] = "256–511 Byte Frames Transmitted",
    [33] = "512–1023 Byte Frames Transmitted",
    [34] = "1024–1522 Byte Frames Transmitted",
    [35] = "1523–9022 Byte Frames Transmitted",
    [36] = "Valid Bytes Received",
    [37] = "Error Runt Packets Received",
    [38] = "Error Jabber Packets Received"
}

function ncsi_gcpsr.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  dissect_resp_reason_code(tvbuf, pktinfo, tree)
  
  local value = tvbuf(4, 4):uint()
  tree:add(tvbuf(4, 4), "Counters Cleared From Last Read (MS Bits):  "..string.format("0x%08x", value))
  value = tvbuf(8, 4):uint()
  tree:add(tvbuf(8, 4), "Counters Cleared From Last Read (LS Bits):  "..string.format("0x%08x", value))
  
  local offset = 12
  for i = 0, 38, 1 do
    if (i <= 7) or (i == 36) then
      value_ms = tvbuf(offset, 4):uint()
      value_ls = tvbuf(offset + 4, 4):uint()
      tree:add(tvbuf(offset, 8), controller_statistics[i]..":  "..string.format("0x%08x%08x", value_ms, value_ls))
      offset = offset + 8
    else
      value = tvbuf(offset, 4):uint()
      tree:add(tvbuf(offset, 4), controller_statistics[i]..":  "..string.format("0x%08x", value))
      offset = offset + 4     
    end  
   end
  value = tvbuf(offset, 4):uint()
  tree:add(tvbuf(offset, 4), "Checksum:  "..string.format("0x%08x", value))
end

payload_dissectors:add(0x98, ncsi_gcpsr)


---------------------------------------------------------------------------------------------
-- Dissector for Get NC-SI Statistics Command (0x19)

ncsi_gsc  = Proto("NC-SI-GSC", pkt_types[0x19])

function ncsi_gsc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x19, ncsi_gsc)



---------------------------------------------------------------------------------------------
-- Dissector for Get NC-SI Statistics Response (0x99)

ncsi_gnsr  = Proto("NC-SI-GNSR", pkt_types[0x99])

local ncsi_statistics = {
    [0] = "NC-SI Commands Received",
    [1] = "NC-SI Control Packets Dropped",
    [2] = "NC-SI Command Type Errors",
    [3] = "NC-SI Command Checksum Errors",
    [4] = "NC-SI Receive Packets",
    [5] = "NC-SI Transmit Packets",
    [6] = "AENs Sent",
}

function ncsi_gnsr.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  dissect_resp_reason_code(tvbuf, pktinfo, tree)
  
  local value = 0
  local offset = 4
  for i = 0, 6, 1 do
    value = tvbuf(offset, 4):uint()
    tree:add(tvbuf(offset, 4), ncsi_statistics[i]..":  "..string.format("0x%08x", value))
    offset = offset + 4
   end
  value = tvbuf(offset, 4):uint()
  tree:add(tvbuf(offset, 4), "Checksum:  "..string.format("0x%08x", value))
end

payload_dissectors:add(0x99, ncsi_gnsr)



---------------------------------------------------------------------------------------------
-- Dissector for Get NC-SI Pass-through Statistics Command (0x1A)

ncsi_gpsc  = Proto("NC-SI-GPSC", pkt_types[0x1A])

function ncsi_gpsc.dissector(tvbuf, pktinfo, tree)
  common_dissector(tvbuf, pktinfo, tree)
end

payload_dissectors:add(0x1A, ncsi_gpsc)




---------------------------------------------------------------------------------------------
-- Dissector for Get NC-SI Pass-through Statistics Response (0x9A)

ncsi_gnpsr  = Proto("NC-SI-GNPSR", pkt_types[0x9A])

local passthrough_statistics = {
    [0] = "Total Pass-through TX Packets Received (Management Controller to Channel)",
    [1] = "Total Pass-through TX Packets Dropped (Management Controller to Channel)",
    [2] = "Pass-through TX Packet Channel State Errors (Management Controller to Channel)",
    [3] = "Pass-through TX Packet Undersized Errors (Management Controller to Channel)",
    [4] = "Pass-through TX Packet Oversized Errors (Management Controller to Channel)",
    [5] = "Total Pass-through RX Packets Received On the LAN Interface (LAN to Channel)",
    [6] = "Total Pass-through RX Packets Dropped (LAN to Channel)",
    [7] = "Pass-through RX Packet Channel State Errors (LAN to Channel)",
    [8] = "Pass-through RX Packet Undersized Errors (LAN to Channel)",
    [9] = "Pass-through RX Packet Oversized Errors (LAN to Channel)",
}

function ncsi_gnpsr.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  dissect_resp_reason_code(tvbuf, pktinfo, tree)
  
  local value = 0
  local offset = 4
  
  value_ms = tvbuf(offset, 4):uint()
  value_ls = tvbuf(offset + 4, 4):uint()
  tree:add(tvbuf(offset, 8), passthrough_statistics[0]..":  "..string.format("0x%08x%08x", value_ms, value_ls))
  offset = offset + 8
    
  for i = 1, 9, 1 do
    value = tvbuf(offset, 4):uint()
    tree:add(tvbuf(offset, 4), passthrough_statistics[i]..":  "..string.format("0x%08x", value))
    offset = offset + 4
   end
  value = tvbuf(offset, 4):uint()
  tree:add(tvbuf(offset, 4), "Checksum:  "..string.format("0x%08x", value))
end

payload_dissectors:add(0x9A, ncsi_gnpsr)


------------------------------------------------------------------------------------------
-- Dissector for OEM Command (0x50)
-- TODO: OEM-specific



------------------------------------------------------------------------------------------
-- Dissector for OEM Response (0xD0)
-- TODO: OEM-specific


------------------------------------------------------------------------------------------
-- Dissector for AEN Packet (0xFF)
-- TODO: OEM-specific AENs

ncsi_aen = Proto("NC-SI-AEN", pkt_types[0xFF])
local types = {
    [0x00]  = "Link Status Change",
    [0x01]  = "Configuration Required",
    [0x02]  = "Host NC Driver Status Change"
}
local aen_type      = ProtoField.uint8("ncsi.aen.type", "AEN Type", base.HEX, types)
local oem_status    = ProtoField.uint32("ncsi.aen.oem", "OEM Link Status", base.HEX)
local checksum      = ProtoField.uint32("ncsi.aen.cksm", "Checksum", base.HEX)

local host_status = {
    [0] = "Not operational",
    [1] = "Operational"
}
local host_drive_status   = ProtoField.uint32("ncsi.glsr.host_drive_status", "Host NC Driver Status Indication", base.DEC, host_status, 0x1)

ncsi_aen.fields = {aen_type, oem_status, host_drive_status, checksum}

function ncsi_aen.dissector(tvbuf, pktinfo, tree)
  local pktlen = tvbuf:reported_length_remaining()
  if pktlen == 0 then return end
  
  tree:add(aen_type, tvbuf(3, 1))
  local type = tvbuf(3, 1):uint()
  if type == 0x0 then
    local link_status = tree:add(ncsi_aen, tvbuf(0, 4), "Link Status")
    dissect_link_status(tvbuf(4, 4):tvb(), pktinfo, link_status)
    tree:add(oem_status, tvbuf(8, 4))
    tree:add(checksum, tvbuf(12, 4))
  elseif type == 0x1 then
    tree:add(checksum, tvbuf(4, 4))
  elseif type == 0x2 then
    tree:add(host_drive_status, tvbuf(4, 4))
    tree:add(checksum, tvbuf(8, 4))
  elseif type <= 0x7F then  
    --tree:add(aen_type, tvbuf(3, 1), nil, "Reserved")
  else
    --tree:add(aen_type, tvbuf(3, 1), nil, "OEM-specific AENs")
  end
  pktinfo.cols.info:append(" "..types[type])

 end

payload_dissectors:add(0xFF, ncsi_aen)




