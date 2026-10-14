# Private reusable travelers

User wants to enter passenger details privately once, reuse them for bookings,
and keep multiple people (including their wife). They prefer withholding these
details from the agent. This section is a design, not implemented custody.
Current traveler support in `/checkout/profile.json` is local agent-readable
convenience storage. It does not satisfy this requirement. No wife's traveler
details have been provided or saved. Do not request them in chat by default.

## User flow

1. “Add traveler” opens a passkey-authorized private form. Choose a public label
   such as “Me” or “Wife”, enter required details, choose optional document/contact
   fields to remember, and save. Approving storage does not purchase anything.
2. “Book this for Wife” selects an opaque traveler ID. The agent can see labels,
   available field categories, and status, never the saved values.
3. A trusted private fill service sends approved fields only to the selected
   booking merchant. Reuse permission has a clear merchant/field scope; it must
   not authorize arbitrary websites forever. Known approved scopes should avoid
   repeated setup ceremonies. A new recipient/scope needs human review.
4. The normal payment review shows flight, passengers by public label, baggage,
   merchant and exact total. Its approval is separate from saving traveler data.
   Extra browser takeover is reserved for challenges, login, or unsupported entry.
5. Manage multiple travelers in that same private UI: edit, remove, replace
   expired documents, choose booking/contact defaults, and select more than one
   passenger when needed. No silent guess, merge or substitution between people.

## Storage and boundaries

Extend Signer's custody model with independently encrypted traveler records;
do not put legal names, DOB, document numbers or contact values in agent-readable
VFS, operation descriptions, logs, public errors or agent-generated request bodies.
Private form inputs must be encrypted to Signer using the authenticated ceremony
flow. Card, password and verification-code storage remain separate.

Release only scoped, short-lived encrypted field values to the private browser
filler. Bind the grant to the traveler, field set, actual merchant/frame origins,
browser operation and expiry. Reject swapped frames, stale documents, redirects
to a new recipient, replay and multi-passenger mapping ambiguity. Do not trust
merchant-authored field mappings without checking their destination and types.

Autofill alone does not hide data: a merchant can echo names/documents in its
DOM, accessibility tree, title, URL, validation errors and confirmation page.
After private fill, do not resume unrestricted shopping projection of that
document. Provide a constrained non-personal booking summary/status; retain
private control until a fresh safe document exists. A denylist of matching
strings is insufficient. The airline necessarily receives the booked passenger's
details; the claim is to keep them from the agent, not from the airline.

## Implementation order and proof

First land the existing card custody/browser service parents in their responsible
owners' queue. Then implement traveler storage/protocol in Signer, private save
and reuse grants in Broker, private field mapping/fill in Checkout, and opaque
traveler selection in Bloom/Petal guidance. Do not make another stack above
unsettled service parents or write to their owners' heads. No new PR is opened
for this design. BRIJ remains documented as a later independent experiment.

Required boundary evidence: save/edit/delete two people through actual private
ceremony UI, wrong-person and wrong-field rejection, merchant/frame/redirect
binding, expired/replayed grants, logs/VFS/AX/URL/error/confirmation non-disclosure,
agent attempts to read filled pages, and final payment scope unchanged. Test
with synthetic traveler data and no real charge before deployment; follow the
workspace service combination release gates for landing.

