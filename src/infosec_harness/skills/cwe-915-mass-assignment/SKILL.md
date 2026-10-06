---
name: cwe-915-mass-assignment
description: Request data bound wholesale onto model attributes. Use this when the finding is CWE-915/913 or mass assignment.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-915: Mass assignment (improperly controlled object attribute modification)

## Use this skill when

- The finding is classified CWE-915 or CWE-913, or names mass assignment, over-posting or
  auto-binding.
- Request JSON, form data or query parameters are copied onto an object or record without a
  field allow-list: `obj.__dict__.update(data)`, `setattr` in a loop, `Object.assign(user,
  req.body)`, `Model(**data)`, Spring data binding onto an entity.

## Do not use this skill when

- The keys reach `Object.prototype` or another shared prototype — use
  `cwe-1321-prototype-pollution`.
- The values are used to choose a class or function — use `cwe-470-unsafe-reflection`.

## When another skill also applies

- `cwe-1321-prototype-pollution` also fires for JavaScript merges of request bodies. **That
  skill wins** when `__proto__` or `constructor.prototype` keys reach a shared prototype;
  **this skill wins** when the harm is an own attribute of the target object.

## Procedure

**Sink.** The bulk copy from request data onto a persistent or security-relevant object.

**Guard.** An explicit allow-list of updatable fields; a DTO or schema that defines only
safe fields; `attr_accessible`/`@JsonIgnore`/`@InitBinder setAllowedFields`; a check that
rejects unknown keys.

**Neutralized when.** Every attribute the caller must not set (role, `is_admin`, owner id,
balance, verification flag) is outside the allow-list or overwritten after the copy.

**Source.** Keys and values of the request body, form or query string.

## Oracle

Condition: **an attribute the caller must not set changed after a request through the real
update path.** Create the object through the target's own constructor or store with the
protected attribute at its safe value (for example `is_admin=False`), then call the real
update function with a body containing an allowed field plus the protected one.

- `target_reached`: the real update function ran with the body, whether it applied, ignored
  or rejected the protected key.
- `oracle_valid`: the protected attribute starts at its safe value and is read back through the
  target's own getter or store.
- `vulnerability_observed`: the protected attribute holds the caller's value afterwards.
- `positive_control`: setting the attribute directly in the probe changes it and the check
  fires, proving the check reads the right field.
- `negative_control`: a body with only allowed fields updates them, and the check stays silent.

Read the object back through the target's own getter or store, not only the in-memory copy
the probe holds, when the target persists it.

## Language notes

- **Python**: `for k, v in data.items(): setattr(obj, k, v)`, `obj.__dict__.update`,
  `Model.objects.filter(...).update(**data)`, Pydantic models with `extra="allow"`.
- **JavaScript**: `Object.assign`, spread `{...user, ...req.body}`, Mongoose
  `Model.updateOne(filter, req.body)`, Sequelize `update(req.body)` without `fields`.
- **Java**: Spring MVC binding of request parameters onto `@Entity` objects, Jackson
  deserialization onto entities without `@JsonIgnoreProperties`.
- **Perl**: `$obj->{$_} = $params->{$_} for keys %$params`, DBIx::Class `update($params)`.

## Pitfalls

- An attribute that is merely unexpected is not a finding; name why the caller must not set it.
- An allow-list that is applied only on create, not on update, still leaves the update open.
- The protected value may be recomputed on save; read it after the real persistence step.

## Verdict guidance

- `potentially_exploitable`: the protected attribute changed through the real update path;
  name the privilege or data gained.
- `likely_not_exploitable`: the cited allow-list or schema dropped or rejected the key, with
  both controls passing.
- `inconclusive`: persistence or authorization depends on a framework layer you could not run.
