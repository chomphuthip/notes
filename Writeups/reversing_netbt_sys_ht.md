### Reverse Engineering `netbt.sys`'s Hash Table ###

I needed to refresh my RE skills after doing Maldev for a few weeks. Actually 
making stuff really opened my eyes and gave me a really good perspective of
people writing C and C++. I actually implemented my own [generic hash
table](httpd://github.com/chomphuthip/pdd) a few weeks ago so I thought this 
would be the perfect opportunity to use what I learned from writing so much C 
to reverse engineer some cool software.

Hash tables lookups are pretty simple:
1. Hash your key
2. Modulo with the map length
3. Manage collisions based on the implementation
3. Compare key to bucket's key. If key isn't matching, go to next bucket.

The hashing implementation is pretty simple:\
![Hashing and Mod](https://i.imgur.com/Kha239A.png)

I think this is where C really shines as a programming language. In most other
languages, you just use the standard library's hash table implementation which
may or may not do way more than you need.

Being able to hand-implement this lets you decide how lightweight your hashing
function is going to be. My [hash table](https://github.com/chomphuthip/pdd)
uses a Wang hash for 32-bit literals and FNV for strings, but someone might not
need those algorithms. If your keys are already pretty unique (as is the case
with `netbt.sys`) you don't really need to further spread them out.

This hashing algorithm takes the bottom 4 bits, multiplies them by `0x10`, and adds
the bottom 4 bits of the second byte. Then the result is modulo'd against the
map length.

The next thing to identify is how collisions are managed. The easiest way to see
this is to identify what variable is holding the pointer to the current bucket, and
how that variable changes.

If the variable changes by adding some value, collisions are managed using
_open addressing_. This means that the next bucket to try is literally the next
bucket (or `&bucket + N` where `N` is your probing factor).

If the variable changes based on a pointer that it holds, collisions are managed
using _chaining_. This means that the next bucket is pointed to by a pointer in
the current bucket, forming a singly-linked list.

This is the primary searching implementation:\
![Searching Implementation](https://i.imgur.com/MQZhnTH.png)

`next_bucket` is set to the pointer at `bucket + 0x0`, meaning that this
implementation uses _chaining_. Looks like `bucket + 0x48` is a flags field which
is checked to see if the key is variable length or just `0x10` long. After
determining the key length, the provided key is compared with the bucket's key,
stored at `bucket + 0xa4`.

The rest of the function has to do with a child bucket at `bucket + 0x78`.\
![Child bucket implementation](https://i.imgur.com/AJAgAsX.png)

If the bucket has a child bucket, the `child_key` string is compared against the child
bucket's key (another example of C granting you the ability to do/add whatever you want 
in your implementation if you aren't gatekept by skill issues). 

The value pointed to by `output` is set to the pointer of the matching bucket.
