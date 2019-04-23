# Private ride sharing

## Chris' ramblings about revamping this paper around this idea
I was doing some more thinking about this project, and the ride-sharing
application in particular. 2SFE+SGX is well suited for this application.. We
hide the locations of the riders _and_ drivers from the service provider, while
letting the service provider implement its own policy for setting up rides.
(Ultimately the rider and driver agree, and only then do they reveal their
locations to one another.) The policy is implemented in an SGX module; if the
enclave is compromised, then at worst, the service provider learns if the "cost"
of pick is acceptable to the rider. (The rider picks this "cost threshold".)

But this solution can be extended to other applications. There's a whole service
economy in which clients are able to request a job from a pool of "workers", who
are capable of doing that job, but the "cost" of doing that job is not the same
for all of them.  Another example besides ride sharing is "Shipped", an app you
can use to have someone do your grocery shopping. Then there's food-delivery
services, dog-walking services, Airbnb maybe ...

So one way to revamp the paper might be to develop a framework for adding
privacy to these kinds of services. More generally, our solution is useful when
there's a service that's "matching" pairs of entities based on some metric that
can efficiently be computed via GC+OT. By efficient, I mean in O(1) space and
O(1) (or O(log n) on the outside) time. The result of this computation leaks
_something_, but not _everything_ --- hence the use of the enclave.

Which leads me to a title: **The Dating Problem for the new service economy**

Concretely, we would design, implement, and evaluate our own private
ride-sharing app, and talk about why it's better than the papers Joseph pointed
out. (These are documented in `ride.tex` in this directory.`) But we would also
develop a framework for other services. We could even provide a formal
treatment, but it would be technically different than what we've done so far.

## Patrick's response
very interesting take. I like the idea of using an enclave to deal with
inevitable leakage (the loss of which isn't THAT bad, but for which we CAN do
something about). It makes me think of David Evans' two-bit leakage/equality GC
protocol.

## Additional papers to look at:

 * _SRide: A Privacy-Preserving Ridesharing System_, WiSec '18

## Uber
Anecdotely we know the following about Uber's service:
* Rider contacts Uber
* Uber finds three driers for which the trip is the shortest, orders by reputation. Sends request to D1.
* If D1 rejects, then sends to D2.
* if D2 rejects, then sends to D3.
* If D3 rejects, then done.
* Accepting driver contacts rider.
* If client accepts, then do ride().
