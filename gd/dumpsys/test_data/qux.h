
#include "qux_generated.h"
#include "root.h"
#include "root_generated.h"

namespace testing {

class QuxTestDataClass : public DumpsysTestDataClass {
 public:
  TableAddFunction GetTable(flatbuffers::FlatBufferBuilder& builder) override {
    auto name = builder.CreateString("Qux Module String");

    QuxTestSchemaBuilder qux_builder(builder);
    qux_builder.add_qux_private(123);
    qux_builder.add_qux_opaque(456);
    qux_builder.add_qux_anonymized(789);
    qux_builder.add_qux_any(0xabc);
    qux_builder.add_another_field(name);

    auto qux_table = qux_builder.Finish();

    return [qux_table](DumpsysTestDataRootBuilder* builder) { builder->add_qux_module_data(qux_table); };
  }
};

}  // namespace testing
