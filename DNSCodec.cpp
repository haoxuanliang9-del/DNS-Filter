#include "DNSCodec.h"

namespace dns_filter
{

bool DNSCodec::does_need_decoding(const std::vector<uint8_t> &data)
{
    
    if(data.size() < 12) 
    {
        Logger::warn("DNS数据包过短，无法解析");
        return false; // DNS报头至少12字节
    }
    uint8_t flags = data[2];
    if(!(flags & 0x80))
    {
        if((flags & 0x78) == 0)
        {
            int count = 1;
            for (auto it = data.begin() + 12; ; ++it)
            {
                if(it == data.end())
                {
                    Logger::warn("DNS数据包格式错误，查询部分未正确结束");
                    return false;
                }
                auto &byte = *it;
                if(byte==0)
                    break;
                ++count;
            }
            if(data.size() < 14 + count)
            {
                Logger::warn("DNS数据包过短，无法解析查询类型");
                return false;
            }
            uint8_t qtype1 = data[12 + count];
            uint8_t qtype2 = data[13 + count];
            if(qtype1 == 0x00 && (qtype2 == 0x01 || qtype2 == 0x1C))
            {
                return true;
            }
        }
    }
    return false;
}

std::optional<std::string> DNSCodec::parse_query_name(const std::vector<uint8_t> &data)
{
    if (data.size() < 12)
    {
        Logger::warn("DNS数据包过短，无法解析");
        return std::nullopt; 
    }

    std::string domain;

    for(auto it = data.begin() + 12;;++it)
    {
        if (it == data.end())
        {
            Logger::warn("DNS数据包格式错误，查询部分未正确结束");
            return std::nullopt;
        }

        auto &len = *it;
        if((len & 0xFF) == 0)
            break;

        for (uint8_t i = 0; i < len; ++i)
        {
            ++it;
            if (it == data.end())
            {
                Logger::warn("DNS数据包格式错误，查询部分未正确结束");
                return std::nullopt;
            }
            char c = static_cast<char>(*it);
            domain += c;
        }
        domain += ".";
    }

    // 移除末尾多余的点
    if (!domain.empty() && domain.back() == '.') {
        domain.pop_back();
    }

    Logger::info("域名解析成功:" + domain);
    return domain;
}

std::optional<std::vector<uint8_t>> DNSCodec::build_block_response(const std::vector<uint8_t> &request_data)
{
    /*
    QR:1
    AA:0
    TC:0
    RA:=RD
    Z:0
    RCODE:3
    ANCOUNT:0
    NSCOUNT:0
    ARCOUNT:0
    其它与查询报文相同，无资源记录。
    */
    if (request_data.size() < 12)
    {
        Logger::warn("查询报文过短，响应报文构造失败");
        return std::nullopt;
    }
    std::vector<uint8_t> response_data = request_data;

    // 设置byte[2]: QR=1, AA=0, TC=0, OpCode和RD保持不变
    bool rd = response_data[2] & 0x01;
    response_data[2] = (response_data[2] | 0x80) & 0xF9;

    // 设置byte[3]: RA=RD, Z=0, RCODE=3
    response_data[3] = (rd ? 0x80 : 0x00) | 0x03;

    response_data[6] = 0x00;
    response_data[7] = 0x00;
    response_data[8] = 0x00;
    response_data[9] = 0x00;
    response_data[10] = 0x00;
    response_data[11] = 0x00;

    Logger::info("成功构造拦截响应");
    return response_data;
}

bool DNSCodec::is_response(const std::vector<uint8_t> &data)
{
    if (data.size() < 12)
        return false;
    // QR 标志位在 byte[2] 的最高位
    return (data[2] & 0x80) != 0;
}

uint16_t DNSCodec::get_transaction_id(const std::vector<uint8_t> &data)
{
    if (data.size() < 2)
        return 0;
    // Transaction ID 在前两个字节，网络字节序
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}
}