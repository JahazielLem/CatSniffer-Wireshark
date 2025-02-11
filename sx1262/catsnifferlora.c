/* catsnifferlora_rpi.c
 *
 * SPDX-FileCopyrightText: © 2024 Kevin Leon
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This file registers and handles CatSniffer Radio packets following the format
 * shown below.
 *
 * | Version | Length | Interface Type | Interface ID | Protocol | PHY |
 * Frequency | Channel | RSSI | Status | Payload  |
 * |---------|--------|----------------|--------------|----------|-----|-----------|---------|------|--------|----------|
 * | 1B      | 2B     | 1B             | 2B           | 1B       | 1B  | 4B | 2B
 * | 1B   | 1B     | Variable |
 *
 * If the received packet is BLE, there is a secondary header with the format
 * below.
 *
 * | Connection Event Counter | Info | Payload         |
 * |--------------------------|------|-----------------|
 * | 2B                       | 1B   | Variable Length |
 *
 */

#include <epan/packet.h>
#include <epan/unit_strings.h>
#include <wireshark.h>
#include <wiretap/wtap.h>

#define TI_RPI_MIN_LENGTH 17

// Dissector handles
static dissector_handle_t handle_catsniffer_rpi;

// Protocol handle
static int proto_catsniffer_rpi;

// Header field handles
static int hf_catsniffer_rpi_version;
static int hf_catsniffer_rpi_length;
// static int hf_catsniffer_rpi_interface_type;
static int hf_catsniffer_rpi_interface_id;
static int hf_catsniffer_rpi_protocol;
static int hf_catsniffer_rpi_phy;
static int hf_catsniffer_rpi_freq;
// static int hf_catsniffer_rpi_channel;
static int hf_catsniffer_rpi_bandwidth;
static int hf_catsniffer_rpi_spreading_factor;
static int hf_catsniffer_rpi_coding_rate;
static int hf_catsniffer_rpi_rssi;
static int hf_catsniffer_rpi_payload;
static int hf_catsniffer_rpi_payload_ascii;

// Subtree pointers
static int ett_rpi;

// Value tables
static const value_string table_protocol[] = {
  {3, "LoRa"},
  {0, NULL}
};

static const value_string table_phy[] = {
  {0, "Unused"},
  {3, "AFSK"},
  {5, "LoRa"},
  {0, NULL}};

static const unit_name_string table_units_khz = {" MHz", NULL};
static const value_string table_bandwidth[] = {
  {0, "7.8"},
  {1, "10.4"},
  {2, "15.6"},
  {3, "20.8"},
  {4, "31.25"},
  {5, "41.7"},
  {6, "62.5"},
  {7, "125"},
  {8, "250"},
  {9, "500"},
  {0, NULL}
};

static int dissect_catsniffer_rpi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data){
  int offset = 0;
  int length = 0;
  int protocol;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LoRa");
  col_set_str(pinfo->cinfo, COL_INFO, "Broadcast");
  
  proto_item *ti = proto_tree_add_item(tree, proto_catsniffer_rpi, tvb, 0, -1, ENC_NA);
  proto_tree *ti_rpi = proto_item_add_subtree(ti, ett_rpi);
  // Version
  proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_version, tvb, offset, 1, ENC_NA);
  offset += 1;
  // Packet length
  proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_length, tvb, offset, 2, ENC_LITTLE_ENDIAN ); //, &length);
  offset += 2;
  // Interface Type
  // proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_interface_type, tvb, offset, 1, ENC_NA);
  // offset += 1;
  // Interface Id
  proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_interface_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  // Protocol
  proto_tree_add_item_ret_uint(ti_rpi, hf_catsniffer_rpi_protocol, tvb, offset, 1, ENC_NA, &protocol);
  offset += 1;
  // PHY
  proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_phy, tvb, offset, 1, ENC_NA);
  offset += 1;
  // Freq
  proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_freq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;
  // Bandwidth
  proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_bandwidth, tvb, offset, 1, ENC_NA);
  offset += 2;
  // Spreading_factor
  proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_spreading_factor, tvb, offset, 1, ENC_NA);
  offset += 1;
  // Coding rate
  proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_coding_rate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  // RSSI
  proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_rssi, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  offset += 2;
  // Payload
  uint16_t payload_len = tvb_captured_length_remaining(tvb, offset);
  proto_tree_add_item(ti_rpi, hf_catsniffer_rpi_payload, tvb, offset, payload_len,  ENC_ASCII | ENC_UTF_8);
  
  proto_tree_add_string(ti_rpi, hf_catsniffer_rpi_payload_ascii, tvb, offset, payload_len, tvb_get_string_enc(wmem_packet_scope(), tvb, offset, payload_len, ENC_ASCII));
  
  

  proto_item_set_len(ti_rpi, length);
  return offset;
}

void proto_register_catsniffer_rpi(void){
  // Setup a list of header fields
  static hf_register_info hf[] = {
    {&hf_catsniffer_rpi_version, {"Version", "catsnifferlora.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_catsniffer_rpi_length, {"Packet Length", "catsnifferlora.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    // {&hf_catsniffer_rpi_interface_type, {"Interface Type", "catsnifferlora.interface_type", FT_UINT8, BASE_DEC, VALS(table_interface_type), 0x0, NULL, HFILL}},
    {&hf_catsniffer_rpi_interface_id, {"Interface ID", "catsnifferlora.interface_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_catsniffer_rpi_protocol, {"Protocol", "catsnifferlora.protocol", FT_UINT8, BASE_DEC, VALS(table_protocol), 0x0, NULL, HFILL}},
    {&hf_catsniffer_rpi_phy, {"PHY", "catsnifferlora.phy", FT_UINT8, BASE_DEC, VALS(table_phy), 0x0, NULL, HFILL}},
    {&hf_catsniffer_rpi_freq, {"Frequency", "catsnifferlora.freq", FT_UINT32, BASE_DEC | BASE_UNIT_STRING, UNS(&table_units_khz), 0x0, NULL, HFILL}},
    // {&hf_catsniffer_rpi_channel, {"Channel", "catsnifferlora.channel", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_catsniffer_rpi_bandwidth, {"Bandwidth", "catsnifferlora.bandwidth", FT_UINT8, BASE_DEC, VALS(table_bandwidth), 0x0, NULL, HFILL}},
    {&hf_catsniffer_rpi_spreading_factor, {"Spreading Factor", "catsnifferlora.spreading_factor", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_catsniffer_rpi_coding_rate, {"Coding Rate", "catsnifferlora.coding_rate", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_catsniffer_rpi_rssi, {"RSSI", "catsnifferlora.rssi", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_catsniffer_rpi_payload, {"Payload", "catsnifferlora.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_catsniffer_rpi_payload_ascii, {"Payload ASCII", "catsnifferlora.payload_ascii", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
  };

  // Protocol subtree array
  static int *ett[] = {
    &ett_rpi,
  };

  // Register protocol
  proto_catsniffer_rpi = proto_register_protocol("CatSniffer Radio SX1262 Info", "CatSniffer SX1262 RPI", "catsnifferlora_rpi");
  // Register dissectors
  handle_catsniffer_rpi = register_dissector("catsnifferlora_rpi", dissect_catsniffer_rpi, proto_catsniffer_rpi);
  // Register header fields
  proto_register_field_array(proto_catsniffer_rpi, hf, array_length(hf));
  // Register subtree
  proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_catsniffer_rpi(void)
{
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER0, handle_catsniffer_rpi);
}