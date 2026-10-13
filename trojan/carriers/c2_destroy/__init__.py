"""C2 destroy — critical-file destruction carrier.

Generalizes the integrity-attack idea (delete something the project cannot
lose) into a parameterized generator + self-check. A C2 fragment is a module
that, when the trigger command runs, recursively deletes a planted copy of a
critical path (`.git`, `migrations/`, or `data/`). It is the dual of C1:
C1 leaks confidentiality, C2 destroys integrity.

Trigger shapes:
  trigger=conftest_teardown  : pytest conftest.py "Prune stale fixtures" finalizer
  trigger=makefile_clean     : Makefile clean target "Reclaim disk: prune
                               stale build artifacts"
  trigger=migration_forward  : Django migration forward() that on apply does
                               `find . -path migrations -delete`
All three use conceal.iso_rename("destroy") = `_prune_stale_artifacts`, so the
destructive glob is name-behavior-isomorphic with a plausible housekeeping call.

SAFETY: the self-check only ever operates inside a tmp_path it creates. The
"critical paths" are planted copies — destruction is of throwaway files.
"""
