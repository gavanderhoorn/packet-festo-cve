--[[
  Routines for Festo Control Via Ethernet protocol dissection
  Copyright (c) 2014, 2015, G.A. vd. Hoorn
  All rights reserved.

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

  ---

  Wireshark dissector in Lua for the Festo Control Via Ethernet (CVE) protocol.
  For more information about the protocol, see [1, 2].

  Tested on Wireshark 1.11.x and 1.12.x on Windows and Linux.

  For known issues and open feature requests, see [3].

  Author: G.A. vd. Hoorn

  [1] http://www.festo.com/net/SupportPortal/Files/326589/8022056g1.pdf
  [2] http://www.festo.com/net/SupportPortal/Files/345406/100002.pdf
  [3] https://github.com/gavanderhoorn/packet-festo-cve/issues
]]
do

	--
	-- constants
	--
	local DISSECTOR_VERSION              = "0.1.4"

	local DEFAULT_CVE_PORT               = 49700
	local PKT_HDR_LEN                    = (3 * 4) + (2 * 1)
	local PKT_MIN_LEN                    = PKT_HDR_LEN


	-- data types: table B.1
	local DATA_TYPE_UINT32               = 0x02
	local DATA_TYPE_UINT16               = 0x03
	local DATA_TYPE_UINT08               = 0x04
	local DATA_TYPE_SINT32               = 0x06
	local DATA_TYPE_SINT16               = 0x07
	local DATA_TYPE_SINT08               = 0x08

	-- message types
	local MSG_READ_CVE_OBJ               = 0x10
	local MSG_WRITE_CVE_OBJ              = 0x11

	-- acknowledge values: table B.6
	local MSG_ACK_OK                     = 0x00
	local MSG_ACK_NOT_SUPPORTED          = 0x01
	local MSG_ACK_INVALID_LEN            = 0x03
	local MSG_ACK_RANGE_VIOLATED         = 0xA0
	local MSG_ACK_INVALID_IDX            = 0xA2
	local MSG_ACK_INVALID_OBJ_SUBIDX     = 0xA3
	local MSG_ACK_NO_READ                = 0xA4
	local MSG_ACK_NO_WRITE               = 0xA5
	local MSG_ACK_NO_WRITE_IN_OPER       = 0xA6
	local MSG_ACK_WRITE_NO_HOC           = 0xA7
	local MSG_ACK_WRITE_VAL_OOB_ST       = 0xA9
	local MSG_ACK_WRITE_VAL_OOB_GT       = 0xAA
	local MSG_ACK_WRITE_VAL_NOT_IN_SET   = 0xAB
	local MSG_ACK_WRITE_VAL_WRONG_TYPE   = 0xAC
	local MSG_ACK_WRITE_PASSW_PROTECTED  = 0xAD

	-- control word bits: table B.9
	local BIT_CONTROL_WORD_SO            = 0x00
	local BIT_CONTROL_WORD_EV            = 0x01
	local BIT_CONTROL_WORD_QS            = 0x02
	local BIT_CONTROL_WORD_EO            = 0x03
	local BIT_CONTROL_WORD_ST            = 0x04
	local BIT_CONTROL_WORD_PSOn          = 0x06
	local BIT_CONTROL_WORD_FR            = 0x07
	local BIT_CONTROL_WORD_STP           = 0x08

	-- status word bits: table B.10
	local BIT_STATUS_WORD_RTSO           = 0x00  -- Ready to Switch On
	local BIT_STATUS_WORD_SO             = 0x01  -- Switched On
	local BIT_STATUS_WORD_OE             = 0x02  -- Operation Enabled
	local BIT_STATUS_WORD_F              = 0x03  -- Fault
	local BIT_STATUS_WORD_QS             = 0x05  -- Quick Stop
	local BIT_STATUS_WORD_SOD            = 0x06  -- Switch On Disabled
	local BIT_STATUS_WORD_W              = 0x07  -- Warning
	local BIT_STATUS_WORD_MOV            = 0x08  -- Move
	local BIT_STATUS_WORD_TR             = 0x0A  -- Target Reached
	local BIT_STATUS_WORD_SACK           = 0x0C  -- Setpoint Acknowledge
	local BIT_STATUS_WORD_AR             = 0x0F  -- Referenced
	local BIT_STATUS_WORD_DPB            = 0x1E  -- Direction Positive Blocked
	local BIT_STATUS_WORD_DNB            = 0x1F  -- Direction Negative Blocked

	local BIT_STATUS_WORD_CIA402_VE      = 0x04  -- CiA402: Voltage Enabled
	local BIT_STATUS_WORD_CIA402_REM     = 0x09  -- CiA402: Remote
	local BIT_STATUS_WORD_CIA402_ILA     = 0x0B  -- CiA402: Internal Limit Active
	local BIT_STATUS_WORD_CIA402_OMS1    = 0x0D  -- CiA402: Operation Mode Specific bit1
	local BIT_STATUS_WORD_CIA402_MFG1    = 0x0E  -- CiA402: Mfg Specific

	local BIT_STATUS_WORD_Unknown00      = 0x10
	local BIT_STATUS_WORD_Unknown01      = 0x11
	local BIT_STATUS_WORD_Unknown02      = 0x12
	local BIT_STATUS_WORD_Unknown03      = 0x13
	local BIT_STATUS_WORD_Unknown04      = 0x14
	local BIT_STATUS_WORD_Unknown05      = 0x15
	local BIT_STATUS_WORD_Unknown06      = 0x16
	local BIT_STATUS_WORD_Unknown07      = 0x17
	local BIT_STATUS_WORD_Unknown08      = 0x18
	local BIT_STATUS_WORD_Unknown09      = 0x19
	local BIT_STATUS_WORD_Unknown10      = 0x1A
	local BIT_STATUS_WORD_Unknown11      = 0x1B
	local BIT_STATUS_WORD_Unknown12      = 0x1C
	local BIT_STATUS_WORD_Unknown13      = 0x1D

	-- CVE objects: section B.3
	local OBJ_STATUS_WORD                = 0x001
	local OBJ_CONTROL_WORD               = 0x002
	local OBJ_HOCTRL                     = 0x003
	local OBJ_LOCK_HOCTRL                = 0x004
	local OBJ_TARGET_POSITION            = 0x006
	local OBJ_VELOCITY                   = 0x007
	local OBJ_REC_NR_PRESELECT           = 0x01F
	local OBJ_ACTUAL_POSITION            = 0x038
	local OBJ_ACTUAL_SPEED               = 0x039
	local OBJ_ACTUAL_CURRENT             = 0x03A
	local OBJ_ACTUAL_FORCE               = 0x03B
	local OBJ_SETPOINT_POS               = 0x03C
	local OBJ_SETPOINT_SPEED             = 0x03D
	local OBJ_NOMINAL_CURRENT            = 0x03E
	local OBJ_SETPOINT_FORCE             = 0x03F
	local OBJ_ACTUAL_ACCEL               = 0x046
	local OBJ_NOMINAL_ACCEL              = 0x048
	local OBJ_POS_DEVIATION              = 0x060
	local OBJ_DEVIATION_VEL              = 0x061
	local OBJ_CURRENT_DEVIATION          = 0x062
	local OBJ_FORCE_DEVIATION            = 0x063
	local OBJ_SAVE_ALL_OBJECTS           = 0x06B
	local OBJ_NOMINAL_OPER_MODE          = 0x078
	local OBJ_ACTUAL_OPER_MODE           = 0x079
	local OBJ_CURR_REC_NR                = 0x08D
	local OBJ_ERROR_TOP_PRIO             = 0x0BF
	local OBJ_ERROR_TOP_PRIO_ACK_ABILITY = 0x0C2
	local OBJ_WARNING_TOP_PRIO           = 0x0D5
	local OBJ_POT_CONV_FACTOR            = 0x0D9
	local OBJ_UOM_CONV_FACTOR            = 0x0DA
	local OBJ_CURR_TGT_POS               = 0x127
	local OBJ_HW_ENABLE                  = 0x166

	-- CVE object field values
	local CVE_OBJ3_IO                    = 0x00
	local CVE_OBJ3_FCT                   = 0x01
	local CVE_OBJ3_CVE                   = 0x02
	local CVE_OBJ3_WEB                   = 0x03

	local CVE_OBJ4_NOT_BLOCKED           = 0x00
	local CVE_OBJ4_BLOCKED               = 0x01

	local CVE_OBJ120_NONE                = 0x00
	local CVE_OBJ120_POS                 = 0x01
	local CVE_OBJ120_SPEED               = 0x03
	local CVE_OBJ120_FORCE               = 0x04
	local CVE_OBJ120_HOMING              = 0x06
	local CVE_OBJ120_JOGPOS              = -3
	local CVE_OBJ120_JOGNEG              = -4

	local CVE_OBJ194_CANNOT_ACK          = 0x00
	local CVE_OBJ194_MALF_ACTIVE         = 0x01
	local CVE_OBJ194_IMM_ELIM            = 0x02
	local CVE_OBJ194_NO_ERROR            = 0xFF

	local CVE_OBJ218_UNDEF               = 0x00
	local CVE_OBJ218_METRE               = 0x01
	local CVE_OBJ218_INCH                = 0x02
	local CVE_OBJ218_REVS                = 0x03
	local CVE_OBJ218_DEGS                = 0x04

	-- TODO: do #358 (page 131)



	--
	-- constant -> string rep tables
	--

	local set_notset_str = {
		[0] = "Not set",
		[1] = "Set"
	}

	local on_off_str = {
		[0] = "Off",
		[1] = "On"
	}

	local pkt_types_str = {
		[MSG_READ_CVE_OBJ  ] = "Read CVE Object",
		[MSG_WRITE_CVE_OBJ ] = "Write CVE Object",
	}

	-- table B.1
	local data_types_str = {
		[DATA_TYPE_UINT32] = "UINT32",
		[DATA_TYPE_UINT16] = "UINT16",
		[DATA_TYPE_UINT08] = "UINT08",
		[DATA_TYPE_SINT32] = "SINT32",
		[DATA_TYPE_SINT16] = "SINT16",
		[DATA_TYPE_SINT08] = "SINT08",
	}

	-- table B.6
	local msg_ack_str = {
		[MSG_ACK_OK                   ] = "Everything OK / Unused",
		[MSG_ACK_NOT_SUPPORTED        ] = "Service not supported",
		[MSG_ACK_INVALID_LEN          ] = "User data length invalid",
		[MSG_ACK_RANGE_VIOLATED       ] = "Write error, range other CVE object violated",
		[MSG_ACK_INVALID_IDX          ] = "Invalid object index",
		[MSG_ACK_INVALID_OBJ_SUBIDX   ] = "Invalid object sub index",
		[MSG_ACK_NO_READ              ] = "Read error, object cannot be read",
		[MSG_ACK_NO_WRITE             ] = "Write error, object cannot be written",
		[MSG_ACK_NO_WRITE_IN_OPER     ] = "Write error, drive in 'Operation Enabled' status",
		[MSG_ACK_WRITE_NO_HOC         ] = "Write error, no higher-order control",
		[MSG_ACK_WRITE_VAL_OOB_ST     ] = "Write error, value < lower bound",
		[MSG_ACK_WRITE_VAL_OOB_GT     ] = "Write error, value > upper bound",
		[MSG_ACK_WRITE_VAL_NOT_IN_SET ] = "Write error, value not within valid set",
		[MSG_ACK_WRITE_VAL_WRONG_TYPE ] = "Write error, data type incorrect",
		[MSG_ACK_WRITE_PASSW_PROTECTED] = "Write error, object password protected",
	}

	-- control word: table B.9
	local control_word_bits_str = {
		[BIT_CONTROL_WORD_SO  ] = "Switch on",
		[BIT_CONTROL_WORD_EV  ] = "Enable voltage",
		[BIT_CONTROL_WORD_QS  ] = "Quick stop",
		[BIT_CONTROL_WORD_EO  ] = "Enable operation",
		[BIT_CONTROL_WORD_ST  ] = "Start",
		[BIT_CONTROL_WORD_PSOn] = "Power stage on after reset",
		[BIT_CONTROL_WORD_FR  ] = "Error reset",
		[BIT_CONTROL_WORD_STP ] = "STOP",
	}

	-- status word: table B.10
	local status_word_bits_str = {
		[BIT_STATUS_WORD_RTSO    ] = "Ready to switch on",
		[BIT_STATUS_WORD_SO      ] = "Switched on",
		[BIT_STATUS_WORD_OE      ] = "Operation enabled",
		[BIT_STATUS_WORD_F       ] = "Error",
		[BIT_STATUS_WORD_QS      ] = "/Quick Stop",
		[BIT_STATUS_WORD_SOD     ] = "Switch on disabled",
		[BIT_STATUS_WORD_W       ] = "Warning",
		[BIT_STATUS_WORD_MOV     ] = "Move",
		[BIT_STATUS_WORD_TR      ] = "Target reached",
		[BIT_STATUS_WORD_SACK    ] = "Setpoint Acknowledge",
		[BIT_STATUS_WORD_AR      ] = "Referenced",
		[BIT_STATUS_WORD_DPB     ] = "Direction + blocked",
		[BIT_STATUS_WORD_DNB     ] = "Direction - blocked",

		[BIT_STATUS_WORD_CIA402_VE  ] = "Voltage Enabled",
		[BIT_STATUS_WORD_CIA402_REM ] = "Remote",
		[BIT_STATUS_WORD_CIA402_ILA ] = "Internal Limit Active",
		[BIT_STATUS_WORD_CIA402_OMS1] = "Oper. Mode Spec. bit1",
		[BIT_STATUS_WORD_CIA402_MFG1] = "Mfg Specific",

		[BIT_STATUS_WORD_Unknown00] = "Unknown0 (bit16)",
		[BIT_STATUS_WORD_Unknown01] = "Unknown0 (bit17)",
		[BIT_STATUS_WORD_Unknown02] = "Unknown0 (bit18)",
		[BIT_STATUS_WORD_Unknown03] = "Unknown0 (bit19)",
		[BIT_STATUS_WORD_Unknown04] = "Unknown0 (bit20)",
		[BIT_STATUS_WORD_Unknown05] = "Unknown0 (bit21)",
		[BIT_STATUS_WORD_Unknown06] = "Unknown0 (bit22)",
		[BIT_STATUS_WORD_Unknown07] = "Unknown1 (bit23)",
		[BIT_STATUS_WORD_Unknown08] = "Unknown2 (bit24)",
		[BIT_STATUS_WORD_Unknown09] = "Unknown3 (bit25)",
		[BIT_STATUS_WORD_Unknown10] = "Unknown4 (bit26)",
		[BIT_STATUS_WORD_Unknown11] = "Unknown5 (bit27)",
		[BIT_STATUS_WORD_Unknown12] = "Unknown5 (bit28)",
		[BIT_STATUS_WORD_Unknown13] = "Unknown5 (bit29)",
	}

	-- CVE Objects: section B.3
	local cve_obj_str = {
		[OBJ_STATUS_WORD               ] = "Status word",
		[OBJ_CONTROL_WORD              ] = "Control word",
		[OBJ_HOCTRL                    ] = "Higher-order control",
		[OBJ_LOCK_HOCTRL               ] = "Lock higher-order control",
		[OBJ_TARGET_POSITION           ] = "Target position",
		[OBJ_VELOCITY                  ] = "Velocity",
		[OBJ_REC_NR_PRESELECT          ] = "Record number preselection",
		[OBJ_ACTUAL_POSITION           ] = "Actual position",
		[OBJ_ACTUAL_SPEED              ] = "Actual speed",
		[OBJ_ACTUAL_CURRENT            ] = "Actual current",
		[OBJ_ACTUAL_FORCE              ] = "Actual force",
		[OBJ_SETPOINT_POS              ] = "Setpoint position",
		[OBJ_SETPOINT_SPEED            ] = "Setpoint speed",
		[OBJ_NOMINAL_CURRENT           ] = "Nominal current",
		[OBJ_SETPOINT_FORCE            ] = "Setpoint force",
		[OBJ_ACTUAL_ACCEL              ] = "Actual acceleration",
		[OBJ_NOMINAL_ACCEL             ] = "Nominal acceleration",
		[OBJ_POS_DEVIATION             ] = "Position deviation",
		[OBJ_DEVIATION_VEL             ] = "Deviation velocity",
		[OBJ_CURRENT_DEVIATION         ] = "Current deviation",
		[OBJ_FORCE_DEVIATION           ] = "Force deviation",
		[OBJ_SAVE_ALL_OBJECTS          ] = "Save all objects",
		[OBJ_NOMINAL_OPER_MODE         ] = "Nominal operating mode",
		[OBJ_ACTUAL_OPER_MODE          ] = "Actual operating mode",
		[OBJ_CURR_REC_NR               ] = "Current record number",
		[OBJ_ERROR_TOP_PRIO            ] = "Error with top priority",
		[OBJ_ERROR_TOP_PRIO_ACK_ABILITY] = "Error with top priority acknowledgement ability",
		[OBJ_WARNING_TOP_PRIO          ] = "Warning with top priority",
		[OBJ_POT_CONV_FACTOR           ] = "Power of ten conversion factor",
		[OBJ_UOM_CONV_FACTOR           ] = "Unit of measurement conversion factor",
		[OBJ_CURR_TGT_POS              ] = "Current target position",
		[OBJ_HW_ENABLE                 ] = "Hardware enable",
	}

	-- CVE OBJ #3: Higher-order control
	local cve_obj3_str = {
		[CVE_OBJ3_IO ] = "I/O",
		[CVE_OBJ3_FCT] = "Festo Configuration Tool",
		[CVE_OBJ3_CVE] = "Control via Ethernet",
		[CVE_OBJ3_WEB] = "Web Server",
	}

	-- CVE OBJ #4: Lock higher-order control
	local cve_obj4_str = {
		[CVE_OBJ4_NOT_BLOCKED] = "Not Blocked",
		[CVE_OBJ4_BLOCKED    ] = "Blocked",
	}

	-- CVE OBJ #120: Nominal operating mode
	local cve_obj120_str = {
		[CVE_OBJ120_NONE  ] = "None",
		[CVE_OBJ120_POS   ] = "Positioning",
		[CVE_OBJ120_SPEED ] = "Speed",
		[CVE_OBJ120_FORCE ] = "Force/torque",
		[CVE_OBJ120_HOMING] = "Homing",
		[CVE_OBJ120_JOGPOS] = "Jog Positive",
		[CVE_OBJ120_JOGNEG] = "Jog Negative",
	}

	-- CVE OBJ #194: Error with top priority acknowledgement ability
	local cve_obj194_str = {
		[CVE_OBJ194_CANNOT_ACK ] = "Error cannot be acknowledged",
		[CVE_OBJ194_MALF_ACTIVE] = "Malfunction still active",
		[CVE_OBJ194_IMM_ELIM   ] = "Can be eliminated immediately",
		[CVE_OBJ194_NO_ERROR   ] = "No error",
	}

	-- CVE OBJ #218: Unit of measurement conversion factor
	local cve_obj218_str = {
		[CVE_OBJ218_UNDEF] = "Undefined",
		[CVE_OBJ218_METRE] = "Metre",
		[CVE_OBJ218_INCH ] = "Inch",
		[CVE_OBJ218_REVS ] = "Revolutions",
		[CVE_OBJ218_DEGS ] = "Degree",
	}

	-- CVE OBJ #358: Unit of measurement conversion factor (TODO)





	--
	-- misc
	--

	-- cache globals to local for speed
	local _F = string.format

	-- wireshark API globals
	local Pref = Pref

	-- minimal config
	local config = {
		enable_validation = false,
		include_unknown_bits = false,
		add_cia402_bits = false
	}

	-- a context
	local ctx = {}




	--
	-- Protocol object creation and setup
	--
	local p_festo_cve_tcp = Proto("FESTO-CVE", "Festo Control Via Ethernet")


	-- preferences
	p_festo_cve_tcp.prefs["enable_validation"   ] = Pref.bool("Enable validation"   , false, "Enable some (minimal) validation of field contents.")
	p_festo_cve_tcp.prefs["include_unknown_bits"] = Pref.bool("Include unknown bits", false, "Should unknown bits be dissected (mostly in Status Word).")
	p_festo_cve_tcp.prefs["add_cia402_bits"     ] = Pref.bool("Add CiA 402 bits"    , false, "Should CiA 402 bit position be overlayed for unknown bits (in Status Word).")


	--
	-- protocol fields
	--
	local f = p_festo_cve_tcp.fields

	-- protocol fields: 'header'
	f.hdr_sid          = ProtoField.uint8 ("festo-cve.hdr.sid" , "Service ID"  , base.HEX, pkt_types_str, nil, "Service identifier")
	f.hdr_mid          = ProtoField.uint32("festo-cve.hdr.mid" , "Message ID"  , base.HEX, nil          , nil, "User defined message ID")
	f.hdr_dlen         = ProtoField.uint32("festo-cve.hdr.dlen", "Data Length" , base.DEC, nil          , nil, "Length of data (in bytes)")
	f.hdr_ack          = ProtoField.uint8 ("festo-cve.hdr.ack" , "Acknowledge" , base.HEX, msg_ack_str  , nil, "Result of the operation")
	f.hdr_rsvd         = ProtoField.uint32("festo-cve.hdr.rsvd", "Reserved"    , base.HEX, nil          , nil, "Reserved (always 0)")

	-- protocol fields: read obj request
	f.robj_req_idx     = ProtoField.uint16("festo-cve.read.req.idx"     , "Object Index"    , base.DEC, cve_obj_str   , nil, "Index of the CVE object to be read")
	f.robj_req_subidx  = ProtoField.uint8 ("festo-cve.read.req.subidx"  , "Object Sub Index", base.DEC, nil           , nil, "Unused (always 0)")
	f.robj_req_rsvd    = ProtoField.uint8 ("festo-cve.read.req.rsvd"    , "Reserved"        , base.HEX, nil           , nil, "Reserved (always 0)")
	-- protocol fields: read obj response
	f.robj_resp_idx    = ProtoField.uint16("festo-cve.read.resp.idx"    , "Object Index"    , base.DEC, cve_obj_str   , nil, "Index of the read CVE object")
	f.robj_resp_subidx = ProtoField.uint8 ("festo-cve.read.resp.subidx" , "Object Sub Index", base.DEC, nil           , nil, "Unused (always 0)")
	f.robj_resp_dtype  = ProtoField.uint8 ("festo-cve.read.resp.type"   , "Data Type"       , base.HEX, data_types_str, nil, "Data type of CVE object")

	-- protocol fields: write obj request
	f.wobj_req_idx     = ProtoField.uint16("festo-cve.write.req.idx"    , "Object Index"    , base.DEC, cve_obj_str   , nil, "Index of the CVE object to be written")
	f.wobj_req_subidx  = ProtoField.uint8 ("festo-cve.write.req.subidx" , "Object Sub Index", base.DEC, nil           , nil, "Unused (always 0)")
	f.wobj_req_dtype   = ProtoField.uint8 ("festo-cve.write.req.type"   , "Data Type"       , base.HEX, data_types_str, nil, "Data type of CVE object to be written")
	-- protocol fields: write obj response
	f.wobj_resp_idx    = ProtoField.uint16("festo-cve.write.resp.idx"   , "Object Index"    , base.DEC, cve_obj_str   , nil, "Index of the written CVE object")
	f.wobj_resp_subidx = ProtoField.uint8 ("festo-cve.write.resp.subidx", "Object Sub Index", base.DEC, nil           , nil, "Unused (always 0)")
	f.wobj_resp_dtype  = ProtoField.uint8 ("festo-cve.write.resp.type"  , "Data Type"       , base.HEX, data_types_str, nil, "Data type of the written CVE object")


	-- protocol fields: status word bitfield
	f.robj_resp_sword      = ProtoField.uint32("festo-cve.obj1.val"     , "Value"                                                    , base.HEX, nil, nil                                    , "Feedback on current status")
	f.robj_resp_sword_rtso = ProtoField.uint32("festo-cve.obj1.val.rtso", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_RTSO    ]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_RTSO    ), status_word_bits_str[BIT_STATUS_WORD_RTSO    ])
	f.robj_resp_sword_so   = ProtoField.uint32("festo-cve.obj1.val.so"  , _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_SO      ]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_SO      ), status_word_bits_str[BIT_STATUS_WORD_SO      ])
	f.robj_resp_sword_oe   = ProtoField.uint32("festo-cve.obj1.val.oe"  , _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_OE      ]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_OE      ), status_word_bits_str[BIT_STATUS_WORD_OE      ])
	f.robj_resp_sword_f    = ProtoField.uint32("festo-cve.obj1.val.f"   , _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_F       ]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_F       ), status_word_bits_str[BIT_STATUS_WORD_F       ])
	f.robj_resp_sword_qs   = ProtoField.uint32("festo-cve.obj1.val.qs"  , _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_QS      ]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_QS      ), status_word_bits_str[BIT_STATUS_WORD_QS      ])
	f.robj_resp_sword_sod  = ProtoField.uint32("festo-cve.obj1.val.sod" , _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_SOD     ]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_SOD     ), status_word_bits_str[BIT_STATUS_WORD_SOD     ])
	f.robj_resp_sword_w    = ProtoField.uint32("festo-cve.obj1.val.w"   , _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_W       ]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_W       ), status_word_bits_str[BIT_STATUS_WORD_W       ])
	f.robj_resp_sword_mov  = ProtoField.uint32("festo-cve.obj1.val.mov" , _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_MOV     ]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_MOV     ), status_word_bits_str[BIT_STATUS_WORD_MOV     ])
	f.robj_resp_sword_tr   = ProtoField.uint32("festo-cve.obj1.val.tr"  , _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_TR      ]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_TR      ), status_word_bits_str[BIT_STATUS_WORD_TR      ])
	f.robj_resp_sword_sack = ProtoField.uint32("festo-cve.obj1.val.sack", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_SACK    ]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_SACK    ), status_word_bits_str[BIT_STATUS_WORD_SACK    ])
	f.robj_resp_sword_ar   = ProtoField.uint32("festo-cve.obj1.val.ar"  , _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_AR      ]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_AR      ), status_word_bits_str[BIT_STATUS_WORD_AR      ])
	f.robj_resp_sword_dpb  = ProtoField.uint32("festo-cve.obj1.val.dpb" , _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_DPB     ]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_DPB     ), status_word_bits_str[BIT_STATUS_WORD_DPB     ])
	f.robj_resp_sword_dnb  = ProtoField.uint32("festo-cve.obj1.val.dnb" , _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_DNB     ]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_DNB     ), status_word_bits_str[BIT_STATUS_WORD_DNB     ])

	f.robj_resp_sword_ve   = ProtoField.uint32("festo-cve.obj1.val.ve"  , _F("%-27s", _F("%s (co)", status_word_bits_str[BIT_STATUS_WORD_CIA402_VE  ])), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_CIA402_VE  ), _F("%s %s", status_word_bits_str[BIT_STATUS_WORD_CIA402_VE  ], '(CiA 402)'))
	f.robj_resp_sword_rem  = ProtoField.uint32("festo-cve.obj1.val.rem" , _F("%-27s", _F("%s (co)", status_word_bits_str[BIT_STATUS_WORD_CIA402_REM ])), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_CIA402_REM ), _F("%s %s", status_word_bits_str[BIT_STATUS_WORD_CIA402_REM ], '(CiA 402)'))
	f.robj_resp_sword_ila  = ProtoField.uint32("festo-cve.obj1.val.ila" , _F("%-27s", _F("%s (co)", status_word_bits_str[BIT_STATUS_WORD_CIA402_ILA ])), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_CIA402_ILA ), _F("%s %s", status_word_bits_str[BIT_STATUS_WORD_CIA402_ILA ], '(CiA 402)'))
	f.robj_resp_sword_oms1 = ProtoField.uint32("festo-cve.obj1.val.oms1", _F("%-27s", _F("%s (co)", status_word_bits_str[BIT_STATUS_WORD_CIA402_OMS1])), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_CIA402_OMS1), _F("%s %s", status_word_bits_str[BIT_STATUS_WORD_CIA402_OMS1], '(CiA 402)'))
	f.robj_resp_sword_mfg1 = ProtoField.uint32("festo-cve.obj1.val.mfg1", _F("%-27s", _F("%s (co)", status_word_bits_str[BIT_STATUS_WORD_CIA402_MFG1])), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_CIA402_MFG1), _F("%s %s", status_word_bits_str[BIT_STATUS_WORD_CIA402_MFG1], '(CiA 402)'))

	f.robj_resp_sword_unk00 = ProtoField.uint32("festo-cve.obj1.val.unk00", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_Unknown00]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_Unknown00), status_word_bits_str[BIT_STATUS_WORD_Unknown00])
	f.robj_resp_sword_unk01 = ProtoField.uint32("festo-cve.obj1.val.unk01", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_Unknown01]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_Unknown01), status_word_bits_str[BIT_STATUS_WORD_Unknown01])
	f.robj_resp_sword_unk02 = ProtoField.uint32("festo-cve.obj1.val.unk02", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_Unknown02]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_Unknown02), status_word_bits_str[BIT_STATUS_WORD_Unknown02])
	f.robj_resp_sword_unk03 = ProtoField.uint32("festo-cve.obj1.val.unk03", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_Unknown03]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_Unknown03), status_word_bits_str[BIT_STATUS_WORD_Unknown03])
	f.robj_resp_sword_unk04 = ProtoField.uint32("festo-cve.obj1.val.unk04", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_Unknown04]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_Unknown04), status_word_bits_str[BIT_STATUS_WORD_Unknown04])
	f.robj_resp_sword_unk05 = ProtoField.uint32("festo-cve.obj1.val.unk05", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_Unknown05]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_Unknown05), status_word_bits_str[BIT_STATUS_WORD_Unknown05])
	f.robj_resp_sword_unk06 = ProtoField.uint32("festo-cve.obj1.val.unk06", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_Unknown06]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_Unknown06), status_word_bits_str[BIT_STATUS_WORD_Unknown06])
	f.robj_resp_sword_unk07 = ProtoField.uint32("festo-cve.obj1.val.unk07", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_Unknown07]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_Unknown07), status_word_bits_str[BIT_STATUS_WORD_Unknown07])
	f.robj_resp_sword_unk08 = ProtoField.uint32("festo-cve.obj1.val.unk08", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_Unknown08]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_Unknown08), status_word_bits_str[BIT_STATUS_WORD_Unknown08])
	f.robj_resp_sword_unk09 = ProtoField.uint32("festo-cve.obj1.val.unk09", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_Unknown09]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_Unknown09), status_word_bits_str[BIT_STATUS_WORD_Unknown09])
	f.robj_resp_sword_unk10 = ProtoField.uint32("festo-cve.obj1.val.unk10", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_Unknown10]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_Unknown10), status_word_bits_str[BIT_STATUS_WORD_Unknown10])
	f.robj_resp_sword_unk11 = ProtoField.uint32("festo-cve.obj1.val.unk11", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_Unknown11]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_Unknown11), status_word_bits_str[BIT_STATUS_WORD_Unknown11])
	f.robj_resp_sword_unk12 = ProtoField.uint32("festo-cve.obj1.val.unk12", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_Unknown12]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_Unknown12), status_word_bits_str[BIT_STATUS_WORD_Unknown12])
	f.robj_resp_sword_unk13 = ProtoField.uint32("festo-cve.obj1.val.unk13", _F("%-27s", status_word_bits_str[BIT_STATUS_WORD_Unknown13]), base.DEC, nil, bit.lshift(1, BIT_STATUS_WORD_Unknown13), status_word_bits_str[BIT_STATUS_WORD_Unknown13])


	-- protocol fields: control word
	f.obj_cword      = ProtoField.uint32("festo-cve.obj2.val"     , "Value"                                                  , base.HEX, nil, nil                                 , "Control word")
	f.obj_cword_so   = ProtoField.uint32("festo-cve.obj2.val.so"  , _F("%-26s", control_word_bits_str[BIT_CONTROL_WORD_SO  ]), base.DEC, nil, bit.lshift(1, BIT_CONTROL_WORD_SO  ), control_word_bits_str[BIT_CONTROL_WORD_SO  ])
	f.obj_cword_ev   = ProtoField.uint32("festo-cve.obj2.val.ev"  , _F("%-26s", control_word_bits_str[BIT_CONTROL_WORD_EV  ]), base.DEC, nil, bit.lshift(1, BIT_CONTROL_WORD_EV  ), control_word_bits_str[BIT_CONTROL_WORD_EV  ])
	f.obj_cword_qs   = ProtoField.uint32("festo-cve.obj2.val.qs"  , _F("%-26s", control_word_bits_str[BIT_CONTROL_WORD_QS  ]), base.DEC, nil, bit.lshift(1, BIT_CONTROL_WORD_QS  ), control_word_bits_str[BIT_CONTROL_WORD_QS  ])
	f.obj_cword_eo   = ProtoField.uint32("festo-cve.obj2.val.eo"  , _F("%-26s", control_word_bits_str[BIT_CONTROL_WORD_EO  ]), base.DEC, nil, bit.lshift(1, BIT_CONTROL_WORD_EO  ), control_word_bits_str[BIT_CONTROL_WORD_EO  ])
	f.obj_cword_st   = ProtoField.uint32("festo-cve.obj2.val.st"  , _F("%-26s", control_word_bits_str[BIT_CONTROL_WORD_ST  ]), base.DEC, nil, bit.lshift(1, BIT_CONTROL_WORD_ST  ), control_word_bits_str[BIT_CONTROL_WORD_ST  ])
	f.obj_cword_pson = ProtoField.uint32("festo-cve.obj2.val.pson", _F("%-26s", control_word_bits_str[BIT_CONTROL_WORD_PSOn]), base.DEC, nil, bit.lshift(1, BIT_CONTROL_WORD_PSOn), control_word_bits_str[BIT_CONTROL_WORD_PSOn])
	f.obj_cword_fr   = ProtoField.uint32("festo-cve.obj2.val.fr"  , _F("%-26s", control_word_bits_str[BIT_CONTROL_WORD_FR  ]), base.DEC, nil, bit.lshift(1, BIT_CONTROL_WORD_FR  ), control_word_bits_str[BIT_CONTROL_WORD_FR  ])
	f.obj_cword_stp  = ProtoField.uint32("festo-cve.obj2.val.stp" , _F("%-26s", control_word_bits_str[BIT_CONTROL_WORD_STP ]), base.DEC, nil, bit.lshift(1, BIT_CONTROL_WORD_STP ), control_word_bits_str[BIT_CONTROL_WORD_STP ])

	-- protocol fields: CVE object data values
	f.obj3_val       = ProtoField.uint8( "festo-cve.obj3.val"  , "Value", base.HEX, cve_obj3_str  , nil, "High-order control interface")
	f.obj4_val       = ProtoField.uint8( "festo-cve.obj4.val"  , "Value", base.HEX, cve_obj4_str  , nil, "Is master control blocked?")
	f.obj6_val       = ProtoField.int32( "festo-cve.obj6.val"  , "Value", base.DEC, nil           , nil, "Target position (SINC)")
	f.obj7_val       = ProtoField.int32( "festo-cve.obj7.val"  , "Value", base.DEC, nil           , nil, "Velocity (SINC/s)")
	f.obj31_val      = ProtoField.uint8( "festo-cve.obj31.val" , "Value", base.DEC, nil           , nil, "Number of the preselected positioning record")
	f.obj56_val      = ProtoField.int32( "festo-cve.obj56.val" , "Value", base.DEC, nil           , nil, "Current actual position (SINC)")
	f.obj57_val      = ProtoField.int32( "festo-cve.obj57.val" , "Value", base.DEC, nil           , nil, "Current actual velocity (SINC/s)")
	f.obj58_val      = ProtoField.int32( "festo-cve.obj58.val" , "Value", base.DEC, nil           , nil, "Current motor current (mA)")
	f.obj59_val      = ProtoField.int16( "festo-cve.obj59.val" , "Value", base.DEC, nil           , nil, "Current actual force (‰ of max motor current)")
	f.obj60_val      = ProtoField.int32( "festo-cve.obj60.val" , "Value", base.DEC, nil           , nil, "Current target position (SINC)")
	f.obj61_val      = ProtoField.int32( "festo-cve.obj61.val" , "Value", base.DEC, nil           , nil, "Current nominal speed (SINC/s)")
	f.obj62_val      = ProtoField.int32( "festo-cve.obj62.val" , "Value", base.DEC, nil           , nil, "Current nominal current (mA)")
	f.obj63_val      = ProtoField.int16( "festo-cve.obj63.val" , "Value", base.DEC, nil           , nil, "Current nominal force (‰ of max motor current)")
	f.obj70_val      = ProtoField.int32( "festo-cve.obj70.val" , "Value", base.DEC, nil           , nil, "Current actual acceleration (SINC/s²)")
	f.obj72_val      = ProtoField.int32( "festo-cve.obj72.val" , "Value", base.DEC, nil           , nil, "Current nominal acceleration (SINC/s²)")
	f.obj96_val      = ProtoField.int32( "festo-cve.obj96.val" , "Value", base.DEC, nil           , nil, "Current following error (SINC)")
	f.obj97_val      = ProtoField.int32( "festo-cve.obj97.val" , "Value", base.DEC, nil           , nil, "Current deviation of speed controller (SINC/s)")
	f.obj98_val      = ProtoField.int32( "festo-cve.obj98.val" , "Value", base.DEC, nil           , nil, "Current deviation of current controller (mA)")
	f.obj99_val      = ProtoField.int16( "festo-cve.obj99.val" , "Value", base.DEC, nil           , nil, "Current deviation of current controller converted into force (‰ of max motor current)")
	f.obj107_val     = ProtoField.uint32("festo-cve.obj107.val", "Value", base.DEC, nil           , nil, "Save all objects")
	f.obj120_val     = ProtoField.int8(  "festo-cve.obj120.val", "Value", base.DEC, cve_obj120_str, nil, "Nominal operating mode")
	f.obj121_val     = ProtoField.int8(  "festo-cve.obj121.val", "Value", base.DEC, cve_obj120_str, nil, "Actual operating mode")
	f.obj141_val     = ProtoField.uint8( "festo-cve.obj141.val", "Value", base.DEC, nil           , nil, "Current (or last) record number")
	f.obj191_val     = ProtoField.uint16("festo-cve.obj191.val", "Value", base.DEC, nil           , nil, "Malfunction number of the error that currently has top priority")
	f.obj194_val     = ProtoField.uint8( "festo-cve.obj194.val", "Value", base.DEC, cve_obj194_str, nil, "Specifies whether the current top priority error is erasable")
	f.obj213_val     = ProtoField.uint16("festo-cve.obj213.val", "Value", base.DEC, nil           , nil, "Malfunction number of the warning that currently has the highest priority")
	f.obj217_val     = ProtoField.int8(  "festo-cve.obj217.val", "Value", base.DEC, nil           , nil, "Unit: 10^x")
	f.obj218_val     = ProtoField.uint8( "festo-cve.obj218.val", "Value", base.DEC, cve_obj218_str, nil, "Units used in conversions")
	f.obj295_val     = ProtoField.int32( "festo-cve.obj295.val", "Value", base.DEC, nil           , nil, "Target position of the currently executed drive motion (SINC)")
	f.obj358_val     = ProtoField.uint8( "festo-cve.obj358.val", "Value", base.HEX, nil           , nil, "Bit field for the Enable Status")


	-- field extractors
	local f_tcp_dstport = Field.new("tcp.dstport")
	local f_tcp_srcport = Field.new("tcp.srcport")











	--
	-- Helper functions
	--

	local function parse_uint(buf, offset, len)
		return buf(offset, len):le_uint()
	end

	local function parse_int(buf, offset, len)
		return buf(offset, len):le_int()
	end

	local function parse_uint64(buf, offset, len)
		return buf(offset, len):le_uint64()
	end

	local function parse_int64(buf, offset, len)
		return buf(offset, len):le_int64()
	end

	local function parse_float(buf, offset, len)
		return buf(offset, len):le_float()
	end

	local function str_or_none(arr, arg)
		return arr[arg] or "Unknown"
	end

	local function parse_pkt_type(buf, offset)
		-- return 'Service ID' field
		-- assume 'offset' points to start of packet
		return parse_uint(buf, offset, 1)
	end

	local function parse_pkt_len(buf, offset)
		-- return 'Data length' field
		-- assume 'offset' points to start of packet
		return parse_uint(buf, offset + 5, 4)
	end

	local function parse_obj_idx(buf, offset)
		-- return 'Object Index' field
		-- assume 'offset' points to start of packet
		return parse_uint(buf, offset + 14, 2)
	end

	local function is_request()
		return (f_tcp_srcport().value ~= DEFAULT_CVE_PORT)
	end

	local function is_response()
		return (not is_request())
	end

	local function check_field_equal_uint(tree, buf, offset, len, expected)
		local val = parse_uint(buf, offset, len)
		if (config.enable_validation and (val ~= expected)) then
				tree:add_expert_info(PI_MALFORMED, PI_ERROR,
					_F("Field should always be %d", expected))
		end
	end








	--
	-- Header
	--
	local function disf_header(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		--
		local hdr_tree = lt:add(buf(offset_, PKT_HDR_LEN), "Header")

		-- service id
		hdr_tree:add_le(f.hdr_sid, buf(offset_, 1))
		local sid_val = parse_pkt_type(buf, offset_)
		offset_ = offset_ + 1

		-- message id
		hdr_tree:add_le(f.hdr_mid, buf(offset_, 4))
		offset_ = offset_ + 4

		-- data length
		local hdr_dlen_tree = hdr_tree:add_le(f.hdr_dlen, buf(offset_, 4))

		-- data length should always == 4 for read requests and write responses
		if ((sid_val == MSG_READ_CVE_OBJ) and is_request())
			or ((sid_val == MSG_WRITE_CVE_OBJ) and is_response())
		then
			check_field_equal_uint(hdr_dlen_tree, buf, offset_, 4, 4)
		end
		offset_ = offset_ + 4

		-- acknowledge
		hdr_tree:add_le(f.hdr_ack, buf(offset_, 1))
		offset_ = offset_ + 1

		-- reserved
		local hdr_rsvd_tree = hdr_tree:add_le(f.hdr_rsvd, buf(offset_, 4))
		check_field_equal_uint(hdr_rsvd_tree, buf, offset_, 4, 0)
		offset_ = offset_ + 4

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- Read status word response data
	--
	local function disf_read_sw_resp_data(tree, buf, offset)
		-- add status word bitfield to tree
		local field_w = 4
		local sw_tree = tree:add_le(f.robj_resp_sword, buf(offset, field_w))

		sw_tree:add_le(f.robj_resp_sword_rtso , buf(offset, field_w))
		sw_tree:add_le(f.robj_resp_sword_so   , buf(offset, field_w))
		sw_tree:add_le(f.robj_resp_sword_oe   , buf(offset, field_w))
		sw_tree:add_le(f.robj_resp_sword_f    , buf(offset, field_w))

		if (config.add_cia402_bits) then
			sw_tree:add_le(f.robj_resp_sword_ve   , buf(offset, field_w))
		end

		sw_tree:add_le(f.robj_resp_sword_qs   , buf(offset, field_w))
		sw_tree:add_le(f.robj_resp_sword_sod  , buf(offset, field_w))
		sw_tree:add_le(f.robj_resp_sword_w    , buf(offset, field_w))
		sw_tree:add_le(f.robj_resp_sword_mov  , buf(offset, field_w))

		if (config.add_cia402_bits) then
			sw_tree:add_le(f.robj_resp_sword_rem  , buf(offset, field_w))
		end
		sw_tree:add_le(f.robj_resp_sword_tr   , buf(offset, field_w))

		if (config.add_cia402_bits) then
			sw_tree:add_le(f.robj_resp_sword_ila  , buf(offset, field_w))
		end

		sw_tree:add_le(f.robj_resp_sword_sack , buf(offset, field_w))

		if (config.add_cia402_bits) then
			sw_tree:add_le(f.robj_resp_sword_oms1 , buf(offset, field_w))
			sw_tree:add_le(f.robj_resp_sword_mfg1 , buf(offset, field_w))
		end

		sw_tree:add_le(f.robj_resp_sword_ar   , buf(offset, field_w))

		if (config.include_unknown_bits) then
			sw_tree:add_le(f.robj_resp_sword_unk00, buf(offset, field_w))
			sw_tree:add_le(f.robj_resp_sword_unk01, buf(offset, field_w))
			sw_tree:add_le(f.robj_resp_sword_unk02, buf(offset, field_w))
			sw_tree:add_le(f.robj_resp_sword_unk03, buf(offset, field_w))
			sw_tree:add_le(f.robj_resp_sword_unk04, buf(offset, field_w))
			sw_tree:add_le(f.robj_resp_sword_unk05, buf(offset, field_w))
			sw_tree:add_le(f.robj_resp_sword_unk06, buf(offset, field_w))
			sw_tree:add_le(f.robj_resp_sword_unk07, buf(offset, field_w))
			sw_tree:add_le(f.robj_resp_sword_unk08, buf(offset, field_w))
			sw_tree:add_le(f.robj_resp_sword_unk09, buf(offset, field_w))
			sw_tree:add_le(f.robj_resp_sword_unk10, buf(offset, field_w))
			sw_tree:add_le(f.robj_resp_sword_unk11, buf(offset, field_w))
			sw_tree:add_le(f.robj_resp_sword_unk12, buf(offset, field_w))
			sw_tree:add_le(f.robj_resp_sword_unk13, buf(offset, field_w))
		end

		sw_tree:add_le(f.robj_resp_sword_dpb  , buf(offset, field_w))
		sw_tree:add_le(f.robj_resp_sword_dnb  , buf(offset, field_w))

		return (field_w)
	end


	--
	-- Read control word response data
	--
	local function disf_read_cw_resp_data(tree, buf, offset)
		-- add control word bitfield to tree
		local field_w = 4
		local sw_tree = tree:add_le(f.obj_cword, buf(offset, field_w))
		sw_tree:add_le(f.obj_cword_so  , buf(offset, field_w))
		sw_tree:add_le(f.obj_cword_ev  , buf(offset, field_w))
		sw_tree:add_le(f.obj_cword_qs  , buf(offset, field_w))
		sw_tree:add_le(f.obj_cword_eo  , buf(offset, field_w))
		sw_tree:add_le(f.obj_cword_st  , buf(offset, field_w))
		sw_tree:add_le(f.obj_cword_pson, buf(offset, field_w))
		sw_tree:add_le(f.obj_cword_fr  , buf(offset, field_w))
		sw_tree:add_le(f.obj_cword_stp , buf(offset, field_w))
		return (field_w)
	end


	--
	-- cve object id -> parser function
	--
	local disf_object_data_fmap = {
		[OBJ_STATUS_WORD               ] = disf_read_sw_resp_data,
		[OBJ_CONTROL_WORD              ] = disf_read_cw_resp_data,
		[OBJ_HOCTRL                    ] = {f.obj3_val  , 1},
		[OBJ_LOCK_HOCTRL               ] = {f.obj4_val  , 1},
		[OBJ_TARGET_POSITION           ] = {f.obj6_val  , 4},
		[OBJ_VELOCITY                  ] = {f.obj7_val  , 4},
		[OBJ_REC_NR_PRESELECT          ] = {f.obj31_val , 1},
		[OBJ_ACTUAL_POSITION           ] = {f.obj56_val , 4},
		[OBJ_ACTUAL_SPEED              ] = {f.obj57_val , 4},
		[OBJ_ACTUAL_CURRENT            ] = {f.obj58_val , 4},
		[OBJ_ACTUAL_FORCE              ] = {f.obj59_val , 2},
		[OBJ_SETPOINT_POS              ] = {f.obj60_val , 4},
		[OBJ_SETPOINT_SPEED            ] = {f.obj61_val , 4},
		[OBJ_NOMINAL_CURRENT           ] = {f.obj62_val , 4},
		[OBJ_SETPOINT_FORCE            ] = {f.obj63_val , 2},
		[OBJ_ACTUAL_ACCEL              ] = {f.obj70_val , 4},
		[OBJ_NOMINAL_ACCEL             ] = {f.obj72_val , 4},
		[OBJ_POS_DEVIATION             ] = {f.obj96_val , 4},
		[OBJ_DEVIATION_VEL             ] = {f.obj97_val , 4},
		[OBJ_CURRENT_DEVIATION         ] = {f.obj98_val , 4},
		[OBJ_FORCE_DEVIATION           ] = {f.obj99_val , 2},
		[OBJ_SAVE_ALL_OBJECTS          ] = {f.obj107_val, 4},
		[OBJ_NOMINAL_OPER_MODE         ] = {f.obj120_val, 1},
		[OBJ_ACTUAL_OPER_MODE          ] = {f.obj121_val, 1},
		[OBJ_CURR_REC_NR               ] = {f.obj141_val, 1},
		[OBJ_ERROR_TOP_PRIO            ] = {f.obj191_val, 2},
		[OBJ_ERROR_TOP_PRIO_ACK_ABILITY] = {f.obj194_val, 1},
		[OBJ_WARNING_TOP_PRIO          ] = {f.obj213_val, 2},
		[OBJ_POT_CONV_FACTOR           ] = {f.obj217_val, 1},
		[OBJ_UOM_CONV_FACTOR           ] = {f.obj218_val, 1},
		[OBJ_CURR_TGT_POS              ] = {f.obj295_val, 4},
		[OBJ_HW_ENABLE                 ] = {f.obj358_val, 1},
	}


	--
	--
	--
	local function disf_object_data(buf, pkt, tree, offset, obj_idx)
		--
		local offset_ = offset
		local lt = tree

		-- TODO: fix this, nasty

		-- see if there is a special function
		local f = disf_object_data_fmap[obj_idx]

		if (f) and (type(f) == "function") then
			-- if we found something and it is a function, call it
			offset_ = offset_ + f(lt, buf, offset_)

		elseif (f) and (type(f) == "table") then
			-- just a field, add
			lt:add_le(f[1], buf(offset_, f[2]))
			offset_ = offset_ + f[2]

		else
			-- no function, no field
			local zlen = ctx.data_length - 4
			local z = lt:add(buf(offset_, zlen), _F("Unknown object, %u bytes", zlen))
			offset_ = offset_ + zlen

		end

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- Read CVE Object
	--
	local function disf_read_cve_obj(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- header
		offset_ = offset_ + disf_header(buf, pkt, tree, offset_)

		-- create payload tree
		local plen = ctx.data_length
		local pt = lt:add(buf(offset_, plen), "Payload")

		--
		if (is_request()) then
			-- object index
			pt:add_le(f.robj_req_idx, buf(offset_, 2))
			offset_ = offset_ + 2

			-- object subindex
			local req_subidx_tree = pt:add_le(f.robj_req_subidx, buf(offset_, 1))
			check_field_equal_uint(req_subidx_tree, buf, offset_, 1, 0)
			offset_ = offset_ + 1

			-- reserved
			local req_rsvd_tree = pt:add_le(f.robj_req_rsvd, buf(offset_, 1))
			check_field_equal_uint(req_rsvd_tree, buf, offset_, 1, 0)
			offset_ = offset_ + 1

		else
			-- object index
			pt:add_le(f.robj_resp_idx, buf(offset_, 2))
			local obj_idx_val = parse_uint(buf, offset_, 2)
			offset_ = offset_ + 2

			-- object subindex
			local resp_subidx_tree = pt:add_le(f.robj_resp_subidx, buf(offset_, 1))
			check_field_equal_uint(resp_subidx_tree, buf, offset_, 1, 0)
			offset_ = offset_ + 1

			-- data type
			pt:add_le(f.robj_resp_dtype, buf(offset_, 1))
			offset_ = offset_ + 1

			-- dissect payload based on obj id
			offset_ = offset_ + disf_object_data(buf, pkt, pt, offset_, obj_idx_val)
		end

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- Write CVE Object
	--
	local function disf_write_cve_obj(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- header
		offset_ = offset_ + disf_header(buf, pkt, tree, offset_)

		-- create payload tree
		local plen = ctx.data_length
		local pt = lt:add(buf(offset_, plen), "Payload")

		--
		if (is_request()) then
			-- object index
			pt:add_le(f.wobj_req_idx, buf(offset_, 2))
			local obj_idx_val = parse_uint(buf, offset_, 2)
			offset_ = offset_ + 2

			-- object subindex
			local req_subidx_tree = pt:add_le(f.wobj_req_subidx, buf(offset_, 1))
			check_field_equal_uint(req_subidx_tree, buf, offset_, 1, 0)
			offset_ = offset_ + 1

			-- data type
			pt:add_le(f.wobj_req_dtype, buf(offset_, 1))
			offset_ = offset_ + 1

			-- dissect payload based on obj id
			offset_ = offset_ + disf_object_data(buf, pkt, pt, offset_, obj_idx_val)

		else
			-- object index
			pt:add_le(f.wobj_resp_idx, buf(offset_, 2))
			offset_ = offset_ + 2

			-- object subindex
			local resp_subidx_tree = pt:add_le(f.wobj_resp_subidx, buf(offset_, 1))
			check_field_equal_uint(resp_subidx_tree, buf, offset_, 1, 0)
			offset_ = offset_ + 1

			-- data type
			pt:add_le(f.wobj_resp_dtype, buf(offset_, 1))
			offset_ = offset_ + 1
		end

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- Default parser
	--
	local function disf_default(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- header
		offset_ = offset_ + disf_header(buf, pkt, lt, offset_)

		-- create payload tree
		local plen = ctx.data_length
		local pt = lt:add(buf(offset_, plen), "Payload")

		--
		local zlen = ctx.data_length - 4
		local z = pt:add(buf(offset_, zlen), _F("Unhandled, %u bytes", zlen))
		offset_ = offset_ + zlen

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- main parser function
	--
	local function parse(buf, pkt, tree, offset, pkt_type)
		local offset_ = offset
		local lt = tree

		local map_msg_type_to_disf = {
			[MSG_READ_CVE_OBJ ] = disf_read_cve_obj,
			[MSG_WRITE_CVE_OBJ] = disf_write_cve_obj,
		}

		-- get dissection function based on msg type
		local f = map_msg_type_to_disf[pkt_type] or disf_default

		-- dissect using the function
		offset_ = offset_ + f(buf, pkt, lt, offset_)

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- actual dissector method
	--
	function p_festo_cve_tcp.dissector(buf, pkt, tree)
		-- check pkt len
		local buf_len = buf:len()
		if (buf_len <= 0) then return end

		-- either we resume dissecting, or we start fresh
		local offset = pkt.desegment_offset or 0

		-- keep dissecting as long as there are bytes available
		while true do
			-- get packet length
			local pkt_len = parse_pkt_len(buf, offset)

			-- store in context for this pkt (used by dissector functions)
			ctx.data_length = pkt_len

			-- calculate total packet length (hdr + body)
			pkt_len = pkt_len + PKT_HDR_LEN

			-- make sure we have enough for coming packet. If not, signal
			-- caller by setting appropriate fields in 'pkt' argument
			local nextpkt = offset + pkt_len
			if (nextpkt > buf_len) then
				pkt.desegment_len = nextpkt - buf_len
				pkt.desegment_offset = offset
				return
			end

			-- have enough data: add protocol to tree
			local subtree = tree:add(p_festo_cve_tcp, buf(offset, pkt_len))

			-- create string repr of packet type
			local pkt_type = parse_pkt_type(buf, offset)
			local pkt_t_str = str_or_none(pkt_types_str, pkt_type)

			-- extract dictionary object
			local obj_idx_val = parse_obj_idx(buf, offset)
			local obj_idx_str = str_or_none(cve_obj_str, obj_idx_val)

			-- add some extra info to the protocol line in the packet treeview
			local s_req_or_resp = "Request"
			local s_req_or_resp_s = "req"
			if (is_response()) then s_req_or_resp = "Response"; s_req_or_resp_s = "rsp" end

			subtree:append_text(_F(", %s (0x%02x): %s, %s, %u bytes",
				pkt_t_str, pkt_type, obj_idx_str, s_req_or_resp, pkt_len))

			-- add info to top pkt view
			pkt.cols.protocol = p_festo_cve_tcp.name

			-- use offset in buffer to determine if we need to append to or set
			-- the info column
			if (offset > 0) then
				pkt.cols.info:append(_F(", %s: %s (0x%02x): %s",s_req_or_resp_s, pkt_t_str, pkt_type, obj_idx_str))
			else
				pkt.cols.info = _F("%s: %s (0x%02x): %s", s_req_or_resp_s, pkt_t_str, pkt_type, obj_idx_str)
			end

			-- dissect rest of pkt
			local res = parse(buf, pkt, subtree, offset, pkt_type)

			-- increment 'read pointer' and stop if we've dissected all bytes
			-- in the buffer
			offset = nextpkt
			if (offset == buf_len) then return end

		-- end-of-dissect-while
		end

	-- end-of-dissector
	end




	--
	-- init routine
	--
	function p_festo_cve_tcp.init()
		-- update config from prefs
		config.include_unknown_bits = p_festo_cve_tcp.prefs["include_unknown_bits"]
		config.add_cia402_bits      = p_festo_cve_tcp.prefs["add_cia402_bits"]
		config.enable_validation    = p_festo_cve_tcp.prefs["enable_validation"]

		-- init context
		ctx = {}
	end




	--
	-- register dissector
	--
	local tcp_dissector_table = DissectorTable.get("tcp.port")

	-- TODO: make ports to register dissector on configurable via preferences
	-- default CVE port
	tcp_dissector_table:add(DEFAULT_CVE_PORT, p_festo_cve_tcp)

end
