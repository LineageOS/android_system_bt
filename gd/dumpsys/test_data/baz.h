
#include "baz_generated.h"
#include "root.h"
#include "root_generated.h"

namespace testing {

class BazTestDataClass : public DumpsysTestDataClass {
 public:
  TableAddFunction GetTable(flatbuffers::FlatBufferBuilder& builder) override {
    int value = 0;

    auto sub_name_any = builder.CreateString("Baz Subtable Any");
    auto sub_name_private = builder.CreateString("Baz Subtable Private");
    auto sub_name_opaque = builder.CreateString("Baz Subtable Opaque");
    auto sub_name_anonymized = builder.CreateString("Baz Subtable Anonymized");

    auto any_subtable = CreateBazSubTableAny(builder, ++value, 1, 2, 3, sub_name_any);
    auto private_subtable = CreateBazSubTablePrivate(builder, ++value, sub_name_private);
    auto opaque_subtable = CreateBazSubTableOpaque(builder, ++value, sub_name_opaque);
    auto anonymized_subtable = CreateBazSubTableAnonymized(builder, ++value, sub_name_anonymized);

    BazTestSchemaBuilder baz_builder(builder);
    baz_builder.add_sub_table_any(any_subtable);
    baz_builder.add_sub_table_private(private_subtable);
    baz_builder.add_sub_table_opaque(opaque_subtable);
    baz_builder.add_sub_table_anonymized(anonymized_subtable);
    auto baz_table = baz_builder.Finish();

    return [baz_table](DumpsysTestDataRootBuilder* builder) { builder->add_baz_module_data(baz_table); };
  }
};

}  // namespace testing
