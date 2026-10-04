import assert from "node:assert/strict";
import test from "node:test";
import { QueryClient } from "@tanstack/react-query";
import { queries, queryKeys } from "../api/queries.ts";

test("shared runtime observers use one cache entry and retain their refresh interval", async () => {
  const client = new QueryClient();
  const original = globalThis.fetch;
  let requests = 0;
  try {
    globalThis.fetch = async () => { requests++; return Response.json({environment: "local"}); };
    const [a,b] = await Promise.all([client.fetchQuery(queries.runtime()),client.fetchQuery(queries.runtime())]);
    assert.deepEqual(a,b); assert.equal(requests,1);
    assert.equal(queries.runtime().refetchInterval,30000);
    assert.equal(queries.qualification().refetchInterval,30000);
    assert.equal(queries.experiments().refetchInterval,10000);
    assert.equal(queries.metrics().refetchInterval,10000);
  } finally { globalThis.fetch = original; client.clear(); }
});
test("review invalidation targets the same run cache and leaves other findings intact", async () => {
 const client = new QueryClient();
 try {
  client.setQueryData(queries.run("one").queryKey,{id:"one"});
  client.setQueryData(queries.run("two").queryKey,{id:"two"});
  await client.invalidateQueries({queryKey:queryKeys.run("one")});
  assert.equal(client.getQueryState(queryKeys.run("one")).isInvalidated,true);
  assert.equal(client.getQueryState(queryKeys.run("two")).isInvalidated,false);
 } finally { client.clear(); }
});
test("workflow findings retain real pagination and operational population", async () => {
 const original = globalThis.fetch;
 try {
  globalThis.fetch = async path => {
    const url = new URL(path,"http://localhost");
    assert.equal(url.searchParams.get("batch_id"),"batch");
    assert.equal(url.searchParams.get("offset"),"10");
    assert.equal(url.searchParams.get("limit"),"10");
    assert.equal(url.searchParams.get("population"),"operational");
    return Response.json({items:[]});
  };
  await queries.workflowFindings("batch",10).queryFn();
  assert.equal(queries.experiment(undefined).enabled,false);
 } finally { globalThis.fetch = original; }
});
