Architecture
============

This section explains how the vulnerability results are obtained.

:git+linux-security-vulns:`This repository <+>` has continuous integration
pipelines split in two groups, the build pipelines:

::

     Source           |      Builds       |    Released
                            ┌──────────┐
     Linux Kernel ─────────►│verhaal.db├──┬──► Daily
    (all history)           └──────────┘  │
                            ┌───────┐     │
   Vulns CVE data ─────────►│post.db├─────┘
                            └───────┘
                            ┌───────┐
      Source code ─────────►│grondig├────────► On changes
                            └───────┘

And check pipelines:

::

          Input        |  Tool       |  Output

          verhaal.db ──┐
                       │
                       │  ┌───────┐
             post.db ──┼─►│grondig├───► Vulnerabilities
                       │  └───────┘     (matched CVEs)
                       │
   ┌────────────────┐  │
   │Query:          │  │
   │- stable-tag    ├──┘
   │- cherry-picked │
   │- compiled-files│
   └────────────────┘


The artifacts from the build step are stored in three stable URLs:

- https://github.com/sashalevin/verhaal/releases/download/db-latest/verhaal.db.xz
- https://github.com/analogdevicesinc/linux-security-vulns/releases/download/latest/post.db.xz
- https://github.com/analogdevicesinc/linux-security-vulns/releases/download/latest/grondig

The Vulns CVE data is obtained from https://git.kernel.org/pub/scm/linux/security/vulns.git,
(sparse-checkout ``./cve``).

.. caution::

   The check step is a **demo** and should not be used in production. Please
   mirror the OSV, NVD, and other sources instead of fetching **every time** on
   the pipelines.

:ref:`grondig` is a tool for querying CVEs for a SBOM. To obtain the summary
and score of the CVEs, the check step also has an enrichment job that combines:

- | https://storage.googleapis.com/osv-vulnerabilities/Linux/all.zip
  | Daily `OSV <https://osv.dev>`__ schema entries for the 'Linux' ecosystem.
- | `NIST National Vulnerability Database  <https://nvd.nist.gov/>`__ API calls.

.. _grondig:

Grondig
-------

:git+linux-security-vulns:`Grondig <feature/grondig:tools/grondig>` is a tool
similar to :ref:`strak` but to batch check kernel image SBOMs for CVEs and is
meant for *consumers* of the Linux Kernel. It takes JSON as stdin in the
format:

.. code:: json

   {
     "<uid>": {
       "stable-tag": "<stable-tag>",
       "cherry-picked": ["<sha>"],
       "compiled-files": ["<file>"]
     }
   }

Where:

- ``uid``: A unique identifier, for example the SBOM PURL or equivalent.
- ``stable-tag``: The upstream stable tag, such as `v6.12.88 <https://github.com/gregkh/linux/tree/v6.12.88>`__.
- ``cherry-picked``: List of 40-char SHAs (must match a SHA in the ``.dyad`` files).
- ``compiled-files``: List of files compiled in the kernel image.
  (can be obtained from the `compiled_commands.json <https://github.com/gregkh/linux/blob/master/scripts/clang-tools/gen_compile_commands.py>`__).

And outputs in the JSON format:

.. code:: json

   {
     "<uid>": {
       "cves": ["<cve-id>"]
     }
   }

Where:

- ``uid``: The unique identifier.
- ``cves``: List of CVE IDs, such as ``CVE-2026-31431``.

Therefore, grondig is meant to be an extension to tools such as
`grype <https://github.com/anchore/grype>`__, filling the gap of monitoring
Linux Kernel image builds.

.. _strak:

Strak
-----

`Strak <https://git.kernel.org/pub/scm/linux/security/vulns.git/tree/tools/strak>`__
is a tool to dig the CVE database and either show what CVEs are fixed for
a specific release, or what CVEs are still vulnerable for a specific commit.
If the queried reference is not a stable tag, it falls back to
walking the Linux Kernel tree, requiring it to be cloned alongside. The
advantage is that it allows convoluted verification with commits from different
feature branches that may be released in different stable tags. It has the
limitation of querying one reference at a time and is mostly a maintainer tool.

Recommended workflow
--------------------

The recommended workflow is to generate a SBOM during build that maps those
inputs to grondig; below are tips on how to achieve that.

**Compiled files:** regardless of whether gcc or llvm is used,
`gen_compile_commands.py <https://github.com/gregkh/linux/blob/master/scripts/clang-tools/gen_compile_commands.py>`__
can be invoked to generate ``compiled_commands.json`` containing the list of
source files that were built. Alternatively, a SPDX 3.0 or CycloneDX SBOM can
be provided — :git+linux-security-vulns:`ci:build-grondig-request.py` supports
all three formats.

**Cherry-picked commits:** ensure to use the `-x
<https://git-scm.com/docs/git-cherry-pick#Documentation/git-cherry-pick.txt--x>`__
flag to mark the message with ``cherry-picked from: <sha>``, so they are easily collected.

Then, daily update the database mirrors, and batch check the SBOMs, using a simple formatting
script like :git+linux-security-vulns:`ci:build-grondig-request.py`, and propagate back the
results to your vulnerability management system.

Sample check workflows
~~~~~~~~~~~~~~~~~~~~~~

Two check workflows are provided:

- **CVE tag scan** (``check-tag.yml``): takes a kernel stable tag and returns
  all CVEs affecting that release. In this context, grondig and strak should
  produce the same CVE list.
- **CVE artifact scan** (``check-artifact.yml``): downloads build artifacts
  from a S3 storage to collect SBOMs, format and queries grondig.
  The results are enriched and deployed.

Both workflows share the :git+linux-security-vulns:`ci:check/action.yml`
composite action

Database schemas
----------------

``verhaal.db``
~~~~~~~~~~~~~~

Built from the full Linux Kernel git history. Stores every commit across all
branches, correlating them with their kernel release, mainline upstream SHA,
revert and fix relationships. Also tracks known releases and version ranges,
a SHA1 correction map for malformed ``Fixes:`` tags, and database metadata.

Data source: https://git.kernel.org/pub/scm/linux/kernel/

.. list-table:: commits
   :header-rows: 1
   :widths: 20 15 65

   * - Column
     - Type
     - Description
   * - ``id``
     - TEXT PK
     - 40-char SHA1.
   * - ``release``
     - TEXT
     - Kernel release (e.g. ``6.1.5``).
   * - ``mainline``
     - INTEGER
     - ``1`` = mainline, ``0`` = stable branch.
   * - ``mainline_id``
     - TEXT
     - Upstream mainline SHA1; only set for stable commits.
   * - ``reverts``
     - TEXT
     - SHA1 of the commit this one reverts.
   * - ``fixes``
     - TEXT
     - Space-separated SHA1(s) from ``Fixes:`` tags.

.. list-table:: releases
   :header-rows: 1
   :widths: 20 15 65

   * - Column
     - Type
     - Description
   * - ``release``
     - TEXT PK
     - Version string (e.g. ``6.1``, ``6.1.5``).
   * - ``mainline``
     - INTEGER
     - ``1`` = mainline, ``0`` = stable.

.. list-table:: ranges
   :header-rows: 1
   :widths: 20 15 65

   * - Column
     - Type
     - Description
   * - ``version_from``
     - TEXT
     - Start of the range (e.g. ``6.1.4``).
   * - ``version_to``
     - TEXT
     - End of the range (e.g. ``6.1.5``).
   * - ``mainline``
     - INTEGER
     - ``1`` = mainline, ``0`` = stable.

.. list-table:: fixes
   :header-rows: 1
   :widths: 20 15 65

   * - Column
     - Type
     - Description
   * - ``sha_invalid``
     - TEXT
     - Bad or abbreviated SHA1 found in a ``Fixes:`` tag.
   * - ``sha_valid``
     - TEXT
     - Its correct full SHA1 replacement.

.. list-table:: version
   :header-rows: 1
   :widths: 25 15 60

   * - Column
     - Type
     - Description
   * - ``verhaal_version``
     - TEXT
     - Version of verhaal that created the database.
   * - ``schema_version``
     - TEXT
     - Schema version.

``post.db``
~~~~~~~~~~~

Correlates CVEs with affected source files and with their vulnerable/fix
commits.

Data source: https://git.kernel.org/pub/scm/linux/security/vulns.git/tree/cve

Database tables:

.. list-table:: files
   :header-rows: 1
   :widths: 20 15 65

   * - Column
     - Type
     - Description
   * - ``cve``
     - TEXT
     - CVE identifier (e.g. ``CVE-2024-26592``).
   * - ``file``
     - TEXT
     - Source file path.

.. list-table:: sha
   :header-rows: 1
   :widths: 20 15 65

   * - Column
     - Type
     - Description
   * - ``cve``
     - TEXT
     - CVE identifier.
   * - ``sha``
     - TEXT
     - 40-char commit SHA1.
   * - ``role``
     - INTEGER
     - ``0`` = vulnerable commit, ``1`` = fix commit.
