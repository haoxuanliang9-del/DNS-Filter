#pragma once
#include <vector>
#include <optional>
#include <cstdint>
#include <iostream>
#include "logger.h"



namespace dns_filter
{
class DNSCodec
{
public:
    DNSCodec() = delete;

    // 判断是否需要DNS Filter处理
    static bool does_need_decoding(const std::vector<uint8_t> &data);
    // 解析出查询域名
    static std::optional<std::string> parse_query_name(const std::vector<uint8_t> &data);
    //构造拦截报文
    static std::optional<std::vector<uint8_t>>build_block_response(const std::vector<uint8_t> &request_data);
    // 判断是否为响应报文（QR标志位）
    static bool is_response(const std::vector<uint8_t> &data);
    // 获取 Transaction ID
    static uint16_t get_transaction_id(const std::vector<uint8_t> &data);

};



}