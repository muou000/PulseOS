use bpf_capture::{EventSchema, NormalizedRecord, SchemaRegistry};

#[test]
fn self_described_future_native_version_cannot_use_current_event_decoder() {
    for id in [1,2,3,4,5,6,7,8,0x1000,0x1001] {
        let mut registry=SchemaRegistry::default_pulse_registry();
        let mut schema=registry.lookup(id).unwrap().clone();
        let size=schema.payload_size as usize;
        schema.version=99;
        registry.register(schema);
        let record=NormalizedRecord::new(id,99,100,0,2,2,9,vec![0;size]);
        assert!(registry.validate_record(&record).is_err(),"native event {id} accepted an unsupported version");
    }
}
#[test]
fn native_payload_shape_cannot_be_redefined_by_file_metadata() {
    let mut registry=SchemaRegistry::default_pulse_registry();
    let mut schema=registry.lookup(2).unwrap().clone();
    schema.payload_size=31;
    registry.register(schema);
    let record=NormalizedRecord::new(2,1,100,0,2,2,9,vec![0;31]);
    assert!(registry.validate_record(&record).is_err());
}
#[test]
fn unrelated_custom_schema_is_retained_without_native_reinterpretation() {
    let mut registry=SchemaRegistry::new();
    registry.register(EventSchema {event_id:0x8000,category:"custom".into(),name:"opaque".into(),version:99,payload_size:8,fields:vec![]});
    let record=NormalizedRecord::new(0x8000,99,100,0,0,0,0,vec![7;8]);
    assert!(registry.validate_record(&record).is_ok());
}
