use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

const CERTIFICATE_SCHEMA: &str = "shieldkit-v2-direct/q04-depth4-symbolic-certificate/v2";
const RESULT_SCHEMA: &str = "shieldkit-v2-direct/q04-depth4-rust-certificate-check/v2";
const DEPTH: usize = 4;
const CAPACITY: usize = 1 << DEPTH;
const MAX_NORMAL_COUNT: usize = CAPACITY - 3;
const CONTROL_SKELETONS: usize = 911;
const REPRESENTED_TRANSITIONS: &str = "93928268313";
const ZERO_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug)]
struct CheckError(String);

impl fmt::Display for CheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CheckError {}

type Result<T> = std::result::Result<T, CheckError>;

fn fail<T>(message: impl Into<String>) -> Result<T> {
    Err(CheckError(message.into()))
}

#[derive(Debug)]
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("strict JSON")
            }

            fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(Number::from(value))))
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(Number::from(value))))
            }

            fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                let number =
                    Number::from_f64(value).ok_or_else(|| E::custom("non-finite JSON number"))?;
                Ok(StrictValue(Value::Number(number)))
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(StrictValue(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut input: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut object = Map::new();
                while let Some((key, StrictValue(value))) =
                    input.next_entry::<String, StrictValue>()?
                {
                    if object.insert(key.clone(), value).is_some() {
                        return Err(de::Error::custom(format!("duplicate JSON property {key}")));
                    }
                }
                Ok(StrictValue(Value::Object(object)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

fn strict_json(bytes: &[u8]) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let StrictValue(value) = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| CheckError(format!("invalid strict JSON: {error}")))?;
    deserializer
        .end()
        .map_err(|error| CheckError(format!("trailing JSON data: {error}")))?;
    Ok(value)
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("string JSON"),
        Value::Array(values) => {
            let entries = values.iter().map(canonical_json).collect::<Vec<_>>();
            format!("[{}]", entries.join(","))
        }
        Value::Object(object) => {
            let sorted = object.iter().collect::<BTreeMap<_, _>>();
            let entries = sorted
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("key JSON"),
                        canonical_json(value)
                    )
                })
                .collect::<Vec<_>>();
            format!("{{{}}}", entries.join(","))
        }
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn digest(domain: &str, value: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(canonical_json(value).as_bytes());
    hex::encode(hasher.finalize())
}

fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| CheckError(format!("{label} must be an object")))
}

fn array<'a>(value: &'a Value, label: &str) -> Result<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| CheckError(format!("{label} must be an array")))
}

fn property<'a>(value: &'a Value, key: &str, label: &str) -> Result<&'a Value> {
    object(value, label)?
        .get(key)
        .ok_or_else(|| CheckError(format!("{label}.{key} is missing")))
}

fn exact_keys(value: &Value, expected: &[&str], label: &str) -> Result<()> {
    let actual = object(value, label)?;
    let actual_keys = actual.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_keys = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual_keys != expected_keys {
        return fail(format!(
            "{label} keys differ: actual={actual_keys:?}, expected={expected_keys:?}"
        ));
    }
    Ok(())
}

fn string<'a>(value: &'a Value, label: &str) -> Result<&'a str> {
    value
        .as_str()
        .ok_or_else(|| CheckError(format!("{label} must be a string")))
}

fn integer(value: &Value, low: usize, high: usize, label: &str) -> Result<usize> {
    let number = value
        .as_u64()
        .ok_or_else(|| CheckError(format!("{label} must be an unsigned integer")))?;
    let number =
        usize::try_from(number).map_err(|_| CheckError(format!("{label} does not fit usize")))?;
    if !(low..=high).contains(&number) {
        return fail(format!("{label} must be from {low} through {high}"));
    }
    Ok(number)
}

fn expect_equal(actual: &Value, expected: &Value, label: &str) -> Result<()> {
    if actual != expected {
        return fail(format!(
            "{label} differs\nactual={}\nexpected={}",
            canonical_json(actual),
            canonical_json(expected)
        ));
    }
    Ok(())
}

fn expect_string(value: &Value, expected: &str, label: &str) -> Result<()> {
    if string(value, label)? != expected {
        return fail(format!("{label} differs"));
    }
    Ok(())
}

fn variable(name: &str) -> Value {
    json!({ "kind": "variable", "name": name })
}

fn free_hash(name: &str) -> Value {
    json!({ "kind": "free-hash", "name": name })
}

fn empty_leaf_hash() -> Value {
    json!({ "kind": "empty-leaf-hash" })
}

fn leaf_hash(
    physical_index: usize,
    leaf_type: usize,
    key: Value,
    successor_index: usize,
    successor_key: Value,
) -> Value {
    json!({
        "kind": "leaf-hash",
        "physicalIndex": physical_index,
        "leafType": leaf_type,
        "key": key,
        "successorIndex": successor_index,
        "successorKey": successor_key,
    })
}

fn node_hash(left: Value, right: Value) -> Value {
    json!({ "kind": "node-hash", "left": left, "right": right })
}

fn build_layers(leaves: Vec<Value>) -> Vec<Vec<Value>> {
    let mut layers = vec![leaves];
    for depth in 0..DEPTH {
        let previous = &layers[depth];
        let mut next = Vec::with_capacity(previous.len() / 2);
        for pair in previous.chunks_exact(2) {
            next.push(node_hash(pair[0].clone(), pair[1].clone()));
        }
        layers.push(next);
    }
    layers
}

fn path_for(layers: &[Vec<Value>], index: usize) -> Vec<Value> {
    let mut cursor = index;
    let mut siblings = Vec::with_capacity(DEPTH);
    for layer in layers.iter().take(DEPTH) {
        siblings.push(layer[cursor ^ 1].clone());
        cursor /= 2;
    }
    siblings
}

fn symbolic_field_digest(value: &Value) -> String {
    digest("ShieldKit/Q04/symbolic-witness-field/v1\0", value)
}

fn leaf(
    physical_index: usize,
    leaf_type: usize,
    key: Value,
    successor_index: usize,
    successor_key: Value,
) -> Value {
    let hash = leaf_hash(
        physical_index,
        leaf_type,
        key.clone(),
        successor_index,
        successor_key.clone(),
    );
    json!({
        "physicalIndex": physical_index,
        "leafType": leaf_type,
        "leafHash": hash,
        "key": key,
        "successorIndex": successor_index,
        "successorKey": successor_key,
    })
}

fn witness_leaf(leaf: &Value) -> Result<Value> {
    let leaf_type = integer(property(leaf, "leafType", "leaf")?, 1, 3, "leaf.type")?;
    let kind = match leaf_type {
        1 => "min",
        2 => "normal",
        _ => return fail("maximum sentinel cannot be a predecessor witness"),
    };
    Ok(json!({
        "type": kind,
        "index": property(leaf, "physicalIndex", "leaf")?.clone(),
        "key": symbolic_field_digest(property(leaf, "key", "leaf")?),
        "successorIndex": property(leaf, "successorIndex", "leaf")?.clone(),
        "successorKey":
            symbolic_field_digest(property(leaf, "successorKey", "leaf")?),
    }))
}

fn defaults() -> Vec<Value> {
    let mut values = vec![empty_leaf_hash()];
    for _ in 0..DEPTH {
        let prior = values.last().expect("default").clone();
        values.push(node_hash(prior.clone(), prior));
    }
    values
}

fn expected_adapter_calls(
    predecessor_index: usize,
    append_index: usize,
    pre_layers: &[Vec<Value>],
) -> Vec<Value> {
    let mut calls = Vec::new();
    calls.push(json!({
        "method": "readNode",
        "depth": DEPTH,
        "nodeIndex": 0,
    }));
    calls.push(json!({ "method": "hasNormalKey", "key": variable("X") }));
    calls.push(json!({ "method": "predecessorIndex", "key": variable("X") }));
    calls.push(json!({
        "method": "readLeaf",
        "physicalIndex": predecessor_index,
    }));
    calls.push(json!({ "method": "readLeaf", "physicalIndex": append_index }));
    let mut cursor = predecessor_index;
    for depth in 0..DEPTH {
        calls.push(json!({
            "method": "readNode",
            "depth": depth,
            "nodeIndex": cursor ^ 1,
        }));
        cursor /= 2;
    }
    let mut override_addresses = BTreeSet::new();
    cursor = predecessor_index;
    override_addresses.insert((0, cursor));
    for depth in 0..DEPTH {
        cursor /= 2;
        override_addresses.insert((depth + 1, cursor));
    }
    cursor = append_index;
    for depth in 0..DEPTH {
        let sibling = (depth, cursor ^ 1);
        if !override_addresses.contains(&sibling) {
            let _ = &pre_layers[depth][cursor ^ 1];
            calls.push(json!({
                "method": "readNode",
                "depth": depth,
                "nodeIndex": cursor ^ 1,
            }));
        }
        cursor /= 2;
    }
    calls
}

fn expected_production(
    normal_count: usize,
    predecessor_index: usize,
    successor_index: usize,
) -> Result<(Value, Vec<Value>, Value)> {
    let append_index = normal_count + 2;
    let zero = variable("ZERO");
    let target = variable("X");
    let predecessor_key = if predecessor_index == 0 {
        zero.clone()
    } else {
        variable("K_PREDECESSOR")
    };
    let successor_key = if successor_index == 1 {
        zero.clone()
    } else {
        variable("K_SUCCESSOR")
    };
    let predecessor = leaf(
        predecessor_index,
        if predecessor_index == 0 { 1 } else { 2 },
        predecessor_key.clone(),
        successor_index,
        successor_key.clone(),
    );
    let defaults = defaults();
    let mut pre_leaves = (0..CAPACITY)
        .map(|index| {
            if index <= normal_count + 1 {
                free_hash(&format!("ALLOCATED_LEAF_{index}"))
            } else {
                defaults[0].clone()
            }
        })
        .collect::<Vec<_>>();
    pre_leaves[predecessor_index] = property(&predecessor, "leafHash", "predecessor")?.clone();
    let pre_layers = build_layers(pre_leaves);

    let updated_predecessor = leaf(
        predecessor_index,
        if predecessor_index == 0 { 1 } else { 2 },
        predecessor_key,
        append_index,
        target.clone(),
    );
    let appended = leaf(
        append_index,
        2,
        target.clone(),
        successor_index,
        successor_key,
    );
    let mut intermediate_leaves = pre_layers[0].clone();
    intermediate_leaves[predecessor_index] =
        property(&updated_predecessor, "leafHash", "updated predecessor")?.clone();
    let intermediate_layers = build_layers(intermediate_leaves);
    let mut post_leaves = intermediate_layers[0].clone();
    post_leaves[append_index] = property(&appended, "leafHash", "appended")?.clone();
    let post_layers = build_layers(post_leaves);

    let witness = json!({
        "depth": DEPTH,
        "key": symbolic_field_digest(&target),
        "preRoot": pre_layers[DEPTH][0].clone(),
        "intermediateRoot": intermediate_layers[DEPTH][0].clone(),
        "postRoot": post_layers[DEPTH][0].clone(),
        "predecessor": witness_leaf(&predecessor)?,
        "updatedPredecessor": witness_leaf(&updated_predecessor)?,
        "predecessorPath": path_for(&pre_layers, predecessor_index),
        "append": {
            "index": append_index,
            "emptyLeaf": {
                "type": "empty",
                "index": append_index,
                "key": ZERO_HEX,
                "successorIndex": 0,
                "successorKey": ZERO_HEX,
            },
            "newLeaf": witness_leaf(&appended)?,
            "path": path_for(&intermediate_layers, append_index),
        },
    });

    let mut addresses = BTreeSet::new();
    for leaf_index in [predecessor_index, append_index] {
        let mut cursor = leaf_index;
        addresses.insert((0usize, cursor));
        for depth in 0..DEPTH {
            cursor /= 2;
            addresses.insert((depth + 1, cursor));
        }
    }
    let nodes = addresses
        .into_iter()
        .map(|(depth, node_index)| {
            json!({
                "depth": depth,
                "nodeIndex": node_index,
                "nodeHash": post_layers[depth][node_index].clone(),
            })
        })
        .collect::<Vec<_>>();

    let metrics = json!({
        "leafHashCalls": 3,
        "predecessorValidationLeafHashCalls": 1,
        "mutationLeafHashCalls": 2,
        "nodeHashCalls": 16,
        "predecessorMembershipNodeHashCalls": 4,
        "predecessorUpdateNodeHashCalls": 4,
        "appendNonMembershipNodeHashCalls": 4,
        "appendUpdateNodeHashCalls": 4,
        "nodeReads": 8,
        "rootAdapterNodeReads": 1,
        "pathAdapterNodeReads": 7,
        "logicalPathSiblingLookups": 8,
        "pathOverrideHits": 1,
        "leafReads": 2,
        "orderLookups": 2,
        "treeDepth": 4,
    });
    let production = json!({
        "root": post_layers[DEPTH][0].clone(),
        "witness": witness,
        "nullifierNodes": nodes,
        "nullifierLeaves": [updated_predecessor, appended],
        "metrics": metrics,
    });
    let calls = expected_adapter_calls(predecessor_index, append_index, &pre_layers);
    Ok((production, calls, post_layers[DEPTH][0].clone()))
}

fn expected_skeletons() -> Vec<(usize, usize, usize)> {
    let mut output = Vec::new();
    for normal_count in 0..=MAX_NORMAL_COUNT {
        if normal_count == 0 {
            output.push((0, 0, 1));
            continue;
        }
        let normals = (2..normal_count + 2).collect::<Vec<_>>();
        let mut predecessors = vec![0];
        predecessors.extend(normals.iter().copied());
        let mut successors = vec![1];
        successors.extend(normals.iter().copied());
        for predecessor in &predecessors {
            for successor in &successors {
                if predecessor == successor || (*predecessor == 0 && *successor == 1) {
                    continue;
                }
                output.push((normal_count, *predecessor, *successor));
            }
        }
    }
    output
}

fn expected_universal(
    normal_count: usize,
    predecessor_index: usize,
    successor_index: usize,
) -> Value {
    let mut constraints = Vec::new();
    if predecessor_index != 0 {
        constraints.push(Value::String("K_PREDECESSOR < X".to_owned()));
    }
    if successor_index != 1 {
        constraints.push(Value::String("X < K_SUCCESSOR".to_owned()));
    }
    json!({
        "target": "X",
        "predecessorKey":
            if predecessor_index == 0 { "minimum-sentinel" } else { "K_PREDECESSOR" },
        "successorKey":
            if successor_index == 1 { "maximum-sentinel" } else { "K_SUCCESSOR" },
        "untouchedAllocatedLeafHashes": normal_count + 1,
        "orderConstraints": constraints,
    })
}

fn validate_case(case: &Value, expected: (usize, usize, usize), index: usize) -> Result<()> {
    let label = format!("cases[{index}]");
    exact_keys(
        case,
        &[
            "normalCount",
            "predecessorIndex",
            "successorIndex",
            "appendIndex",
            "universallyQuantified",
            "adapterCallCount",
            "adapterCallsSha256",
            "canonicalPostRootSha256",
            "productionProofSha256",
            "proof",
            "statementSha256",
        ],
        &label,
    )?;
    let (normal_count, predecessor_index, successor_index) = expected;
    if integer(
        property(case, "normalCount", &label)?,
        0,
        MAX_NORMAL_COUNT,
        &format!("{label}.normalCount"),
    )? != normal_count
    {
        return fail(format!("{label}.normalCount differs"));
    }
    if integer(
        property(case, "predecessorIndex", &label)?,
        0,
        CAPACITY - 1,
        &format!("{label}.predecessorIndex"),
    )? != predecessor_index
    {
        return fail(format!("{label}.predecessorIndex differs"));
    }
    if integer(
        property(case, "successorIndex", &label)?,
        1,
        CAPACITY - 1,
        &format!("{label}.successorIndex"),
    )? != successor_index
    {
        return fail(format!("{label}.successorIndex differs"));
    }
    let append_index = normal_count + 2;
    if integer(
        property(case, "appendIndex", &label)?,
        2,
        CAPACITY - 1,
        &format!("{label}.appendIndex"),
    )? != append_index
    {
        return fail(format!("{label}.appendIndex differs"));
    }
    expect_equal(
        property(case, "universallyQuantified", &label)?,
        &expected_universal(normal_count, predecessor_index, successor_index),
        &format!("{label}.universallyQuantified"),
    )?;

    let proof = property(case, "proof", &label)?;
    exact_keys(
        proof,
        &["symbolicAlgebra", "production", "adapterCalls"],
        &format!("{label}.proof"),
    )?;
    expect_string(
        property(proof, "symbolicAlgebra", &format!("{label}.proof"))?,
        "q04-free-hash-term-algebra-v1",
        &format!("{label}.proof.symbolicAlgebra"),
    )?;
    let (expected_production, expected_calls, canonical_post_root) =
        expected_production(normal_count, predecessor_index, successor_index)?;
    expect_equal(
        property(proof, "production", &format!("{label}.proof"))?,
        &expected_production,
        &format!("{label}.proof.production"),
    )?;
    expect_equal(
        property(proof, "adapterCalls", &format!("{label}.proof"))?,
        &Value::Array(expected_calls.clone()),
        &format!("{label}.proof.adapterCalls"),
    )?;
    let call_count = integer(
        property(case, "adapterCallCount", &label)?,
        0,
        100,
        &format!("{label}.adapterCallCount"),
    )?;
    if call_count != expected_calls.len() {
        return fail(format!("{label}.adapterCallCount differs"));
    }
    let expected_calls_digest = digest(
        "ShieldKit/Q04/symbolic-adapter-calls/v1\0",
        &Value::Array(expected_calls),
    );
    expect_string(
        property(case, "adapterCallsSha256", &label)?,
        &expected_calls_digest,
        &format!("{label}.adapterCallsSha256"),
    )?;
    let production_digest = digest(
        "ShieldKit/Q04/symbolic-production-proof/v1\0",
        &expected_production,
    );
    expect_string(
        property(case, "productionProofSha256", &label)?,
        &production_digest,
        &format!("{label}.productionProofSha256"),
    )?;
    let post_root_digest = digest(
        "ShieldKit/Q04/symbolic-post-root/v1\0",
        &canonical_post_root,
    );
    expect_string(
        property(case, "canonicalPostRootSha256", &label)?,
        &post_root_digest,
        &format!("{label}.canonicalPostRootSha256"),
    )?;
    let mut without_statement = case.clone();
    object_mut(&mut without_statement, &label)?.remove("statementSha256");
    let statement_digest = digest("ShieldKit/Q04/symbolic-statement/v2\0", &without_statement);
    expect_string(
        property(case, "statementSha256", &label)?,
        &statement_digest,
        &format!("{label}.statementSha256"),
    )?;
    Ok(())
}

fn object_mut<'a>(value: &'a mut Value, label: &str) -> Result<&'a mut Map<String, Value>> {
    value
        .as_object_mut()
        .ok_or_else(|| CheckError(format!("{label} must be an object")))
}

fn validate_semantic_core(semantic_core: &Value, production_source: &[u8]) -> Result<String> {
    exact_keys(
        semantic_core,
        &[
            "policy",
            "productionSourceSha256",
            "functions",
            "manifestSha256",
        ],
        "semanticCore",
    )?;
    expect_string(
        property(semantic_core, "policy", "semanticCore")?,
        "opaque-field-and-hash-values-may-only-cross-the-semantic-algebra-v1",
        "semanticCore.policy",
    )?;
    let source_sha = sha256_bytes(production_source);
    expect_string(
        property(semantic_core, "productionSourceSha256", "semanticCore")?,
        &source_sha,
        "semanticCore.productionSourceSha256",
    )?;
    let source = std::str::from_utf8(production_source)
        .map_err(|_| CheckError("production source is not UTF-8".to_owned()))?;
    let forbidden = [
        "Buffer",
        "BigInt",
        "frBytes",
        "frBigInt",
        "hashIndexedNullifier",
        "persistentNullifierLeafHash",
    ];
    let functions = array(
        property(semantic_core, "functions", "semanticCore")?,
        "semanticCore.functions",
    )?;
    let expected_names = [
        "validateLeaf",
        "readStoredNode",
        "pathFromStore",
        "pathFromSiblings",
        "witnessLeaf",
        "runPersistentIndexedNullifierSemanticKernel",
    ];
    if functions.len() != expected_names.len() {
        return fail("semanticCore.functions length differs");
    }
    for (index, name) in expected_names.iter().enumerate() {
        let function = &functions[index];
        exact_keys(
            function,
            &["name", "sha256"],
            &format!("semanticCore.functions[{index}]"),
        )?;
        expect_string(
            property(function, "name", "semantic function")?,
            name,
            &format!("semanticCore.functions[{index}].name"),
        )?;
        let body = extract_js_function(source, name)?;
        for token in forbidden {
            if body.contains(token) {
                return fail(format!(
                    "semantic function {name} directly contains forbidden token {token}"
                ));
            }
        }
        if contains_direct_call(&body, "same") {
            return fail(format!(
                "semantic function {name} directly calls forbidden helper same"
            ));
        }
        let function_digest = digest("ShieldKit/Q04/semantic-function/v1\0", &Value::String(body));
        expect_string(
            property(function, "sha256", "semantic function")?,
            &function_digest,
            &format!("semanticCore.functions[{index}].sha256"),
        )?;
    }
    let manifest_digest = digest(
        "ShieldKit/Q04/semantic-core-manifest/v1\0",
        &Value::Array(functions.clone()),
    );
    expect_string(
        property(semantic_core, "manifestSha256", "semanticCore")?,
        &manifest_digest,
        "semanticCore.manifestSha256",
    )?;
    Ok(source_sha)
}

fn contains_direct_call(source: &str, name: &str) -> bool {
    for (start, _) in source.match_indices(name) {
        let before = source[..start].chars().next_back();
        if before.is_some_and(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '$'
        }) {
            continue;
        }
        let tail = &source[start + name.len()..];
        if tail.trim_start().starts_with('(') {
            return true;
        }
    }
    false
}

fn extract_js_function(source: &str, name: &str) -> Result<String> {
    let marker = format!("function {name}");
    let start = source
        .find(&marker)
        .ok_or_else(|| CheckError(format!("production source lacks {name}")))?;
    let relative_open = source[start + marker.len()..]
        .find('{')
        .ok_or_else(|| CheckError(format!("production function {name} has no body")))?;
    let open = start + marker.len() + relative_open;
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    for index in open..bytes.len() {
        let byte = bytes[index];
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
            continue;
        }
        if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth = depth
                .checked_sub(1)
                .ok_or_else(|| CheckError(format!("function {name} brace underflow")))?;
            if depth == 0 {
                return Ok(source[start..=index].to_owned());
            }
        }
    }
    fail(format!("production function {name} is unterminated"))
}

fn validate_certificate(
    certificate: &Value,
    production_source: &[u8],
    checker_source: &[u8],
) -> Result<Value> {
    exact_keys(
        certificate,
        &[
            "schema",
            "status",
            "definition",
            "semanticCore",
            "cases",
            "casesSha256",
            "certificateSha256",
        ],
        "certificate",
    )?;
    expect_string(
        property(certificate, "schema", "certificate")?,
        CERTIFICATE_SCHEMA,
        "certificate.schema",
    )?;
    expect_string(
        property(certificate, "status", "certificate")?,
        "machine-checked-symbolic-template-evidence",
        "certificate.status",
    )?;
    let definition = property(certificate, "definition", "certificate")?;
    exact_keys(
        definition,
        &[
            "depth",
            "capacity",
            "preInsertionNormalCounts",
            "controlSkeletons",
            "representedConcreteRankStateGapTransitions",
            "quotientClaim",
            "universalTemplateClaim",
        ],
        "definition",
    )?;
    expect_equal(
        property(definition, "depth", "definition")?,
        &json!(4),
        "definition.depth",
    )?;
    expect_equal(
        property(definition, "capacity", "definition")?,
        &json!(16),
        "definition.capacity",
    )?;
    expect_equal(
        property(definition, "preInsertionNormalCounts", "definition")?,
        &json!(14),
        "definition.preInsertionNormalCounts",
    )?;
    expect_equal(
        property(definition, "controlSkeletons", "definition")?,
        &json!(CONTROL_SKELETONS),
        "definition.controlSkeletons",
    )?;
    expect_string(
        property(
            definition,
            "representedConcreteRankStateGapTransitions",
            "definition",
        )?,
        REPRESENTED_TRANSITIONS,
        "definition.representedConcreteRankStateGapTransitions",
    )?;
    expect_equal(
        property(definition, "quotientClaim", "definition")?,
        &Value::Bool(false),
        "definition.quotientClaim",
    )?;
    expect_equal(
        property(definition, "universalTemplateClaim", "definition")?,
        &Value::Bool(true),
        "definition.universalTemplateClaim",
    )?;

    let production_source_sha = validate_semantic_core(
        property(certificate, "semanticCore", "certificate")?,
        production_source,
    )?;
    let cases = array(property(certificate, "cases", "certificate")?, "cases")?;
    let expected = expected_skeletons();
    if cases.len() != CONTROL_SKELETONS || cases.len() != expected.len() {
        return fail("certificate control-skeleton count differs");
    }
    for (index, case) in cases.iter().enumerate() {
        validate_case(case, expected[index], index)?;
    }
    let cases_digest = digest(
        "ShieldKit/Q04/depth4-symbolic-cases/v2\0",
        &Value::Array(cases.clone()),
    );
    expect_string(
        property(certificate, "casesSha256", "certificate")?,
        &cases_digest,
        "certificate.casesSha256",
    )?;
    let mut without_digest = certificate.clone();
    object_mut(&mut without_digest, "certificate")?.remove("certificateSha256");
    let certificate_digest = digest(
        "ShieldKit/Q04/depth4-symbolic-certificate/v2\0",
        &without_digest,
    );
    expect_string(
        property(certificate, "certificateSha256", "certificate")?,
        &certificate_digest,
        "certificate.certificateSha256",
    )?;
    Ok(json!({
        "schema": RESULT_SCHEMA,
        "status": "verified",
        "certificateSchema": CERTIFICATE_SCHEMA,
        "certificateSha256": certificate_digest,
        "productionSourceSha256": production_source_sha,
        "checkerSourceSha256": sha256_bytes(checker_source),
        "controlSkeletons": CONTROL_SKELETONS,
        "representedConcreteRankStateGapTransitions": REPRESENTED_TRANSITIONS,
        "proofCalculus": "independent-rust-free-term-tree-reduction-v1",
        "formalJavaScriptSemanticsClaim": false,
        "stateQuotientClaim": false,
        "collisionAssumptionForTermEquality": false,
    }))
}

fn absolute_regular_file(value: &str, label: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return fail(format!("{label} must be absolute"));
    }
    let canonical = fs::canonicalize(&path)
        .map_err(|error| CheckError(format!("{label} cannot be canonicalized: {error}")))?;
    if canonical != path {
        return fail(format!("{label} must already be canonical"));
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| CheckError(format!("{label} cannot be inspected: {error}")))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return fail(format!("{label} must be a direct regular file"));
    }
    Ok(path)
}

fn run(arguments: &[String]) -> Result<Value> {
    if arguments.len() != 3 {
        return fail(
            "usage: shieldkit-v2-q04-certificate CERTIFICATE_JSON PRODUCTION_SOURCE CHECKER_SOURCE",
        );
    }
    let production_path = absolute_regular_file(&arguments[1], "production source")?;
    let checker_path = absolute_regular_file(&arguments[2], "checker source")?;
    let certificate_bytes = if arguments[0] == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|error| CheckError(format!("certificate stdin read failed: {error}")))?;
        bytes
    } else {
        let certificate_path = absolute_regular_file(&arguments[0], "certificate")?;
        fs::read(&certificate_path)
            .map_err(|error| CheckError(format!("certificate read failed: {error}")))?
    };
    let production_source = fs::read(&production_path)
        .map_err(|error| CheckError(format!("production source read failed: {error}")))?;
    let checker_source = fs::read(&checker_path)
        .map_err(|error| CheckError(format!("checker source read failed: {error}")))?;
    let certificate = strict_json(&certificate_bytes)?;
    validate_certificate(&certificate, &production_source, &checker_source)
}

fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match run(&arguments) {
        Ok(result) => println!("{}", canonical_json(&result)),
        Err(error) => {
            eprintln!("Q-04 Rust certificate check failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_json_rejects_duplicate_properties() {
        let error = strict_json(br#"{"a":1,"a":2}"#).unwrap_err();
        assert!(error.to_string().contains("duplicate JSON property a"));
    }

    #[test]
    fn skeleton_enumeration_is_exact() {
        let skeletons = expected_skeletons();
        assert_eq!(skeletons.len(), CONTROL_SKELETONS);
        assert_eq!(skeletons[0], (0, 0, 1));
        assert_eq!(skeletons.last(), Some(&(13, 14, 13)));
        let represented = (0u128..=13)
            .map(|count| {
                let factorial = (1..=count).product::<u128>();
                factorial * (count + 1)
            })
            .sum::<u128>();
        assert_eq!(represented.to_string(), REPRESENTED_TRANSITIONS);
    }

    #[test]
    fn free_term_reduction_has_exact_fixed_work() {
        let (production, calls, _) = expected_production(13, 14, 13).unwrap();
        assert_eq!(calls.len(), 12);
        assert_eq!(
            property(&production, "metrics", "production").unwrap(),
            &json!({
                "leafHashCalls": 3,
                "predecessorValidationLeafHashCalls": 1,
                "mutationLeafHashCalls": 2,
                "nodeHashCalls": 16,
                "predecessorMembershipNodeHashCalls": 4,
                "predecessorUpdateNodeHashCalls": 4,
                "appendNonMembershipNodeHashCalls": 4,
                "appendUpdateNodeHashCalls": 4,
                "nodeReads": 8,
                "rootAdapterNodeReads": 1,
                "pathAdapterNodeReads": 7,
                "logicalPathSiblingLookups": 8,
                "pathOverrideHits": 1,
                "leafReads": 2,
                "orderLookups": 2,
                "treeDepth": 4,
            })
        );
    }
}
