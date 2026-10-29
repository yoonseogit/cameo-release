#include <cstdint>
#include <iomanip>
#include <iostream>

#include <fastdds/rtps/common/CacheChange.h>

int main()
{
    using eprosima::fastrtps::rtps::CacheChange_t;
    using eprosima::fastrtps::rtps::SequenceNumber_t;

    CacheChange_t change;

    const auto base = reinterpret_cast<std::uintptr_t>(&change);
    const auto writer_guid = reinterpret_cast<std::uintptr_t>(&change.writerGUID);
    const auto sequence = reinterpret_cast<std::uintptr_t>(&change.sequenceNumber);
    const auto seq_high = reinterpret_cast<std::uintptr_t>(&change.sequenceNumber.high);
    const auto seq_low = reinterpret_cast<std::uintptr_t>(&change.sequenceNumber.low);
    const auto guid_prefix = reinterpret_cast<std::uintptr_t>(&change.writerGUID.guidPrefix);
    const auto entity_id = reinterpret_cast<std::uintptr_t>(&change.writerGUID.entityId);

    change.sequenceNumber = SequenceNumber_t(0x12345678, 0x9abcdef0u);

    std::cout << "CACHECHANGE_SIZE=" << sizeof(CacheChange_t) << '\n';
    std::cout << "WRITER_GUID_OFFSET=" << (writer_guid - base) << '\n';
    std::cout << "WRITER_GUID_SIZE=" << sizeof(change.writerGUID) << '\n';
    std::cout << "GUID_PREFIX_REL_OFFSET=" << (guid_prefix - writer_guid) << '\n';
    std::cout << "GUID_PREFIX_SIZE=" << sizeof(change.writerGUID.guidPrefix) << '\n';
    std::cout << "ENTITY_ID_REL_OFFSET=" << (entity_id - writer_guid) << '\n';
    std::cout << "ENTITY_ID_SIZE=" << sizeof(change.writerGUID.entityId) << '\n';
    std::cout << "SEQUENCE_OFFSET=" << (sequence - base) << '\n';
    std::cout << "SEQUENCE_SIZE=" << sizeof(change.sequenceNumber) << '\n';
    std::cout << "SEQ_HIGH_REL_OFFSET=" << (seq_high - sequence) << '\n';
    std::cout << "SEQ_LOW_REL_OFFSET=" << (seq_low - sequence) << '\n';
    std::cout << "SEQ_TEST_HIGH=0x" << std::hex << static_cast<std::uint32_t>(change.sequenceNumber.high) << '\n';
    std::cout << "SEQ_TEST_LOW=0x" << std::hex << change.sequenceNumber.low << '\n';
    std::cout << "SEQ_TEST_TO64=0x" << std::hex << change.sequenceNumber.to64long() << '\n';

    return 0;
}
