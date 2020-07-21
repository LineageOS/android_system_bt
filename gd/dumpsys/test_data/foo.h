
#include "foo_generated.h"
#include "root.h"
#include "root_generated.h"

namespace testing {

class FooTestDataClass : public DumpsysTestDataClass {
 public:
  TableAddFunction GetTable(flatbuffers::FlatBufferBuilder& builder) override {
    auto name = builder.CreateString("Foo Module String");
    auto int_string = builder.CreateString("123");
    auto float_string = builder.CreateString("123.456");

    FooTestSchemaBuilder foo_builder(builder);
    foo_builder.add_foo_int_private(123);
    foo_builder.add_foo_int_opaque(123);
    foo_builder.add_foo_int_anonymized(123);
    foo_builder.add_foo_int_any(123);
    foo_builder.add_foo_int_string(int_string);

    foo_builder.add_another_field(name);
    foo_builder.add_foo_float_private(123.456);
    foo_builder.add_foo_float_opaque(123.456);
    foo_builder.add_foo_float_anonymized(123.456);
    foo_builder.add_foo_float_any(123.456);
    foo_builder.add_foo_float_string(float_string);

    auto foo_table = foo_builder.Finish();

    return [foo_table](DumpsysTestDataRootBuilder* builder) { builder->add_foo_module_data(foo_table); };
  }
};

}  // namespace testing
