# Legal, Security & Ethical Compliance Disclaimer

> **Last Updated:** August 2026  
> **Applicability:** Aegis Invariant Kernel Open-Source Projects, Packages, CLI Tools, and Documentation

---

## 1. ⚖️ No Legal, Regulatory, or Compliance Advisory Services

The software, documentation, invariant rule packs (including `@aegis/soc2-guard`, `@aegis/hipaa-guard`, `@aegis/eu-ai-act-guard`, `@aegis/gdpr-guard`, `@aegis/pci-dss-guard`), and compliance report generators provided by the Aegis Invariant Kernel project are **technical policy enforcement and audit trail utilities**.

- **Not Legal Counsel**: Nothing in this software, documentation, or generated reports constitutes legal, regulatory, cybersecurity compliance, or financial advisory advice.
- **Independent Compliance Verification**: Use of Aegis Invariant Kernel does not automatically ensure or confer formal regulatory compliance (e.g., SOC 2 certification, HIPAA compliance, PCI-DSS Level 1 attestation, or EU AI Act Conformity). Organizations deploying Aegis remain solely responsible for conducting independent compliance audits and ensuring adherence to applicable national and international laws.

---

## 2. 🛡️ Defense-in-Depth & Security Limitations

Aegis Invariant Kernel is designed as an **in-process deterministic clearance layer** operating at the application and agent-runtime boundary.

- **Defense-in-Depth Requirement**: Aegis is intended to operate as one component within a layered security architecture (defense-in-depth). It must be paired with standard enterprise security controls, including database-level least-privilege permissions, network isolation, cryptographic key management, authentication/authorization firewalls, and regular vulnerability scanning.
- **Rule Configuration Responsibility**: Aegis enforces deterministic invariants based strictly on the policies configured by the user or organization. Aegis does not guarantee that misconfigured, disabled, or incomplete rule sets will detect every theoretical security threat or unknown vulnerability.

---

## 3. 🏷️ Trademark & Comparative Evaluation Disclaimers

- **Third-Party Trademarks**: All product names, logos, brands, and registered trademarks mentioned within the Aegis repository and documentation (including but not limited to **NVIDIA®**, **NeMo Guardrails®**, **Lakera Guard®**, **Guardrails AI®**, **OpenAI®**, **Anthropic®**, **LangChain®**, **Meta®**, **PostgreSQL®**, **Docker®**, and **Linux®**) are the property of their respective trademark holders.
- **No Endorsement or Affiliation**: The use of third-party company names, trademarks, or product references is strictly for identification, technical compatibility, and comparative benchmarking purposes under nominative fair use. Reference to them does not imply any affiliation, sponsorship, endorsement, or recommendation by the respective trademark owners.
- **Benchmark Reproducibility**: Comparative evaluation metrics published in project documentation reflect empirical tests executed on open-source testbeds under documented hardware and software environments. Performance and accuracy characteristics may vary depending on runtime configuration, machine specifications, and policy definitions.

---

## 4. 🧭 Acceptable Use & Ethical AI Policy

Aegis Invariant Kernel and its accompanying synthetic evaluation datasets (`@aegis-kernel/evals`) are provided strictly for **defensive security enforcement, authorized safety research, and benign agent governance**.

Users, developers, and organizations agree NOT to:
1. Use Aegis software or its adversarial test suites to facilitate, conduct, or test unauthorized cyberattacks, data exfiltration, or penetration testing against systems without explicit, written authorization from the system owners.
2. Employ Aegis to evade lawful law enforcement, regulatory oversight, or mandatory safety standards.
3. Deploy autonomous AI agents equipped with Aegis in safety-critical physical systems (e.g., autonomous vehicle navigation, nuclear control systems, or life-support medical devices) where software failure could directly cause bodily injury, loss of life, or severe environmental damage.

---

## 5. 📜 Warranty Disclaimer & Limitation of Liability

EXCEPT AS EXPRESSLY STATED IN THE APPLICABLE SOFTWARE LICENSE (MIT LICENSE), THE SOFTWARE IS PROVIDED **"AS IS"**, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.

IN NO EVENT SHALL THE AUTHORS, COPYRIGHT HOLDERS, OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
