# Host consumer design decisions

## Keep the selected source checks together

The host consumer accepts one reviewed source contract and one retained archive.
It binds each source to a digest and a full Git commit before execution. It copies
the selected installed sources into a fresh private directory before replay.
Python runs that copy with `-I -S -B`. Candidate bytecode, import hooks and packet
helpers cannot select the reader code.

The following functions keep a complete boundary visible in one place. Their
branch counts come from `radon cc` on the consumer source. These are explicit
exceptions to the default limit of ten; the limit remains in force elsewhere.

| Function | Complexity | Reason to keep these checks together |
| --- | --- | --- |
| `consumer.verify_installation` | 22 | Bounded directory traversal checks the receipt, namespace population, entry types, startup hooks, runtime absence and every selected source digest before any reader import. Splitting individual predicates into wrappers would hide the complete source boundary. |
| `consumer.unpack` | 16 | Archive traversal checks the exact population and each path and file type against the authenticated buffer. These branches describe distinct unsafe archive shapes. Extraction remains inside the same authenticated buffer's lifetime. |
| `consumer.replay` | 13 | Coordination copies and checks the selected source, executes two isolated readers, compares their decisions and exit statuses, and records separate publication, quality and effect decisions. Each branch closes a specific refusal or repeat condition. |
| `consumer.download` | 11 | Network coordination enforces HTTPS, exclusive output creation, declared length, a hard deadline and archive authentication. The cleanup and alarm restoration stay adjacent to their resource acquisition. |
| `verify_native.verify` | 12 | The check coordinates two fresh installations, the original native replay, concrete hostile mutations, a bytecode positive control, replacement recovery and distinct CLI exits. It retains the receipt for each tested boundary. |

No general compatibility layer or alternate import name exists. The reader's
namespace is the exact public package namespace named by the source contract.
Refusal conditions keep their explicit checks. A later change that adds an
independent responsibility must extract that responsibility and reassess these
exceptions.

The host owns its selected interpreter, operating system, build tools and
selection file. Source digests cover reader source bytes; they do not authenticate
the host interpreter or establish outside adoption or independent custody.
