# Mutation checks: vault-grant phase 1a rules

Each guard was broken on purpose, the vault tests were run on fresh XML (the result files deleted
before every run), the named tests went red, and the source was restored in a `finally`. The full
suite was then green again (296 tests, 0 failures). No mutant had a compile error (`e:` lines).

Runner: a Python script that replaces one anchor in the source, runs
`./gradlew --offline testDebugUnitTest --tests 'com.ritwick.sudostamp.vault.*'`, lists the
`<failure>` test cases from `app/build/test-results/testDebugUnitTest/*.xml`, and restores the file.

| # | Guard broken | Mutant | Tests that went red |
|---|---|---|---|
| a | Denylist check returns allow | `Denylist.denies` starts with `if (host.isNotEmpty() \|\| host.isEmpty()) return false` | DenylistTest.invalidHostsAreDenied, DenylistTest.labelRulesAreExactOrContaining, DenylistTest.ownerHostsAddAndRemoveButBuiltInsStay, DenylistTest.serverHostIsDenied, DenylistTest.sharedVectors, ItemRulesTest.everyUriCheckedAgainstTheDenylist, ItemRulesTest.hostRefusedBeforeTheScreen, ItemRulesTest.ownerAndServerLayersApplyToItems |
| b | Suffix match without the dot (`evilexample.com` matches `example.com`) | `GrantHost.matches`: `h.endsWith(".$u")` -> `h.endsWith(u)` | DenylistTest.ownerHostsAddAndRemoveButBuiltInsStay, DenylistTest.sharedVectors, GrantHostTest.matchingRules, GrantHostTest.matchingSection5Vectors, ItemRulesTest.mustMatchTheHost, VaultRulesFuzzTest.matchingAgreesWithLabelReference |
| c | Grant TOTP refusal ignores allowTotp=false | `ItemRules.grantRefusal`: `item.hasTotp && !allowTotp` -> `item.hasTotp && allowTotp && !allowTotp` | ItemRulesTest.totpRefusedUnlessAllowed |
| e | Trailing bytes accepted in grant-request-v1 | `GrantProtocol.parseRequest`: `takeIf { r.atEnd() }` -> `takeIf { r.atEnd() \|\| !r.atEnd() }` | GrantProtocolTest.refusesTrailingBytes, VaultRulesFuzzTest.grantRequestParserAgreesWithReference |
| f | Grant eligibility accepts an item with attachments | `ItemRules.grantRefusal`: the `hasAttachments` line deleted | ItemRulesTest.attachmentsRefused |

There is no (d): direct send (`vault-request-v1`, send eligibility, its tags) was taken out of
this phase, and so were its mutants.
