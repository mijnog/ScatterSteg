# ScatterSteg in 5 levels of difficulty

One idea explained five times, each time to someone who knows more, in the style of WIRED's *5 Levels* videos: a child, a teenager, a college student, a grad student, and an expert. Each level builds on the one before it and is meant to stand on its own.

The idea is **steganography**: hiding a message so well that nobody knows a message is there. ScatterSteg hides messages in photos.

---

## Level 1: Child

**Me:** Do you know what a secret message is?

**Child:** Like a note that only my friend can read?

**Me:** Exactly. Now imagine a note that's so well hidden, nobody even knows there *is* a note. You give your friend a photo of a dog, and the grown-ups just see a dog. But your friend knows the secret word, and when they use it, the photo tells them your message.

**Child:** How does the message get in the picture?

**Me:** A picture on a computer is made of millions of tiny coloured dots. If you look really closely, each dot is just one colour. We change some of the dots *a tiny bit*: a red dot becomes a teeny bit less red. It's such a small change that your eyes can't see it, not even if you look really hard. The pattern of those little changes is the message.

**Child:** Which dots do you change?

**Me:** Good question! If you draw a crayon mark on a clean white wall, everyone sees it. But if you draw it in the middle of a messy scribble, nobody notices. So we put the changes in the messy, busy parts of the picture, like grass or leaves or hair, and keep away from the smooth parts like the sky.

**Child:** What's the secret word for?

**Me:** It does two things. It decides *which* dots hold the message, so someone without it doesn't even know where to look. And it locks the message, like a diary with a key. Even if someone found it, they couldn't read it without the word.

**The big idea:** ScatterSteg hides a locked message in a photo by changing a few tiny dots, in the messy parts, where no one can tell.

---

## Level 2: Teen

**Me:** You know a picture on a computer is made of pixels. Each pixel's colour is stored as numbers: how much red, green and blue, each from 0 to 255. If I change the red from 200 to 201, can you see the difference?

**Teen:** No way.

**Me:** Nobody can. So every number in the picture can carry one hidden bit of information. Even means 0, odd means 1. A photo from your phone has millions of these numbers, so there's a lot of room.

**Teen:** So you just write the message into the picture, one bit per number?

**Me:** That's the oldest trick in the book. It's called LSB embedding, for "least significant bit". The problem is that people have been looking for it for 25 years. Your eyes can't see the change, but a computer program that counts things can. In a real photo, the numbers follow patterns: neighbouring pixels are similar, some values show up as often as others. Overwriting bits disturbs those patterns. A program called a *detector* looks for the disturbance. Old tools like steghide get caught by modern detectors almost every time.

**Teen:** So what does ScatterSteg do differently?

**Me:** Four things.

1. **It changes as few numbers as possible.** Clever maths finds a way to hide the message while changing two to three times fewer numbers than writing it in directly.
2. **It changes them where the photo is busy.** Every number gets a "cost": cheap in textured areas like grass, expensive in smooth areas like a blue sky. ScatterSteg picks the cheapest set of changes that still hides the message.
3. **It scatters them.** Your passphrase decides a secret order to visit the pixels in, so the message isn't in the first few rows. It's spread over the whole photo in a pattern only your passphrase can recreate.
4. **It encrypts the message first.** Even if someone found exactly where it is, they'd get scrambled bytes. And if anyone changes the photo, the message refuses to open rather than giving back something wrong.

**Teen:** So it's undetectable?

**Me:** No, and anyone who says their tool is undetectable is lying. A detector trained on thousands of photos like yours can still catch ScatterSteg a lot of the time, if the message is big. What you can control:

- **Keep the message small.** A short note in a big photo is much safer than a big file.
- **Use a photo nobody else has.** If someone has the original, they can compare the two and see the differences. Don't use a photo you've posted, or one from the internet, and never use the same photo twice.
- **Send the file itself.** Apps like Instagram or WhatsApp shrink and recompress photos, which destroys the message.

---

## Level 3: College student

**Me:** Let's go through what actually happens when you run `scattersteg embed`.

**Step 1: Keys.** You type a passphrase. ScatterSteg runs it through **Argon2id**, a deliberately slow function: about 0.2 seconds and 256 MiB of memory per try. You don't notice that once, but someone guessing passphrases has to pay it for every guess. Argon2id needs a random **salt**, so the same passphrase gives different keys in different images. Out comes a master key, split into two subkeys: a *scatter key* and an *encryption key*.

**Student:** But the person extracting needs the salt before they can make the key. Where is it?

**Me:** That's the chicken-and-egg problem. The salt has to be at positions anyone can find, because you need it *before* you have the key. So it goes in a public region of the image, chosen by a fixed, published shuffle. That's fine for secrecy: the salt isn't secret, it just has to be random. But it's a spot a detector can look at directly, so it has to be hidden as carefully as everything else. We'll come back to that.

**Step 2: Compress and encrypt.** The message is compressed with DEFLATE (the algorithm in zip files) if that makes it shorter, because fewer bits means fewer changes. Then it's encrypted with **XSalsa20-Poly1305**, which also adds an authentication tag. If one bit of the image changes, the tag doesn't match and extraction fails with an error. You never get a corrupted message.

**Step 3: Order.** The scatter key seeds a ChaCha20 random number generator, which drives a Fisher–Yates shuffle of every usable position in the image. That gives a secret order. The message is written along that order, so without the key you don't know where any bit is.

**Step 4: Where the bits live.**
- In a **PNG**, each pixel has red, green and blue values, and each value's lowest bit can carry one bit.
- A **JPEG** doesn't store pixels. It splits the image into 8×8 blocks, takes a discrete cosine transform of each one (turning it into 64 frequency coefficients), divides those by a quantization table and rounds them to integers. That rounding is where JPEG loses information. ScatterSteg changes those rounded integers directly. It never decompresses and recompresses the image, which would leave its own traces. It uses the 63 AC (non-DC) coefficients of each block.

**Student:** Why not just flip the last bit like LSB?

**Me:** Flipping the last bit of 200 gives 201, but flipping 201 gives 200. Values only ever move within their pair: 200↔201, 202↔203. Over a whole image that evens out the counts within each pair, and the **chi-square attack** (Westfeld and Pfitzmann, 1999) spots exactly that. ScatterSteg adds or subtracts 1 instead (±1, "LSB matching"), which changes the bit just the same but doesn't create that pattern. Better still: when two positions both need changing and one holds 200 while the other holds 201, it just *swaps* them. Both bits change, and the image's histogram of values stays exactly the same. On photos, 93–98.5% of a PNG's changes end up as swaps.

**Step 5: Write the file the way it was written.** The output is saved with the cover's own settings: a PNG with the same compression choices, a camera JPEG with the same header and Huffman tables. A detector shouldn't need statistics to notice "this file was rewritten by some unusual program".

**Student:** Is there a header that says "ScatterSteg was here"?

**Me:** None at all. No magic number, no version marker. A header would itself be evidence. The decoder just tries the passphrase: if the authentication tag checks out, there's a message, and if not, it can't tell "wrong passphrase" from "no message". That's deliberate.

---

## Level 4: Grad student

**Me:** You've probably seen steganography framed as **minimizing distortion**. Want to walk through how ScatterSteg fits that?

**Grad student:** Sure. Additive distortion: each cover element *i* gets a cost ρᵢ of changing it, and you minimize the total cost of the changes subject to communicating *m* bits.

**Me:** Right. Two pieces: the costs, and the coder that achieves near-minimal cost.

**The costs.** For PNG, **HILL** (Li, Wang, Huang and Li, 2014): take the absolute residual of a 3×3 KB high-pass filter, average it over 3×3, take the reciprocal, then smooth with a 15×15 mean. Cheap in texture, expensive in smooth regions, and the smoothing spreads the cost so changes don't pile up on edges a detector can model. For JPEG, **UERD** (Guo et al., 2015): a coefficient's cost is its quantization step divided by the energy of its block plus a quarter of its eight neighbours' energy. Energy is the sum of dequantized AC magnitudes. Every AC coefficient is a carrier, zeros included, as in the published scheme. ScatterSteg used to skip coefficients of magnitude below 2, nsF5-style, which crowds changes into fewer coefficients. Measured against DCTR, including all of them helped from 0.2 bits per non-zero AC coefficient up.

**The coder.** **Syndrome-trellis codes** (Filler, Judas and Fridrich, 2011). The message *m* isn't written into the carriers. It's defined as the *syndrome* of the carriers' LSB vector *y* under a public parity-check matrix: H·y = m. H is built from a small random h×w submatrix repeated down a diagonal band (here h = 7, w ≈ n/m). The encoder runs the Viterbi algorithm over a trellis with 2ʰ states to find the *y* closest to the cover's LSBs under the costs. The decoder just multiplies by H, and never needs the costs. At h = 7 it comes close to the rate–distortion bound.

**Grad student:** Binary or ternary?

**Me:** Binary STC with ±1 changes, where the direction is chosen afterwards to set up those value swaps. The published HILL and UERD results assume a ternary coder, where the message also chooses the direction. That's more efficient: against conseal's reference simulators, ScatterSteg makes about 1.75 times as many changes at the same payload. Moving to multi-layer ternary STC is the next planned step. It will cut the number of changes but remove most of the swaps, so it has to be measured, not assumed.

**How it's evaluated.** The figure of merit is **P_E** = min over thresholds of ½(P_FA + P_MD), where 0.5 means the detector is guessing. ScatterSteg has been run against:

- **Classic detectors** (chi-square, sample pair analysis, Ker's adjacency HCF-COM): essentially blind to it.
- **Rich models**, reimplemented in the style of SRM for PNG and DCTR for JPEG, with Kodovský's ensemble classifier: P_E around 0.44 at 0.05 bits per pixel, 0.36 at 0.4 (PNG, HILL).
- **SRNet**, the reference deep network, trained on 7,000 BOSSbase cover/stego pairs at 256×256: P_E 0.26 at 0.2 bits per pixel, 0.13 at 0.4, and 0.08 for JPEG at 0.2 bits per non-zero AC coefficient. That's a warden trained on your cover source, at your payload: the realistic worst case.
- **Off-the-shelf** EfficientNet detectors (Aletheia's, trained on ALASKA2): at chance at 0.05.

**Grad student:** Why at chance there but caught by SRNet?

**Me:** Cover-source mismatch, and training on the actual embedding. Aletheia's models were trained on ALASKA2 and on simulated J-UNIWARD and J-MiPOD, not on ScatterSteg's output. SRNet was trained on exactly the source and payload it was tested on. A detector is only as good as the match between what it learned and what it sees.

**A lesson from the off-the-shelf run.** One of those detectors did catch the old format, at any payload, even with a single-byte message. The cause turned out to be the 32-bit message length, written directly into 32 secret samples: about 16 changes per file that ignored the costs, mostly zeros turned to ±1 in flat JPEG blocks. Sixteen changes out of hundreds of thousands, and a detector picked them up. Now the length is an STC syndrome too, over up to 2,048 samples with costs, and that detector is back at chance. Every single change has to be cost-aware: there's no such thing as an "unimportant" bit. The salt went through the same fix. Written straight in, it was about 64 changes at known positions, and a targeted test found it slightly above chance. Syndrome-coded over a public region of about 8,192 samples, it's down to about 18 changes and the test is at chance.

---

## Level 5: Expert

**Me:** I'd like to talk about where ScatterSteg sits relative to what's actually known, and what it can't do.

**Expert:** Start with the security definition. You're making a statistical claim, not a cryptographic one.

**Me:** Yes. Under Cachin's definition, the goal is a small KL divergence between the cover and stego distributions, and nobody has the cover distribution. Every claim ScatterSteg makes is empirical: these detectors, these cover sources, this P_E. The docs say "harder to detect than steghide and naive LSB at the same payload, against these detectors", not "secure". Kerckhoffs applies in full: the tool is open source, so the right adversary is one who trains a detector on ScatterSteg's own output. SRNet on BOSSbase is a proxy for that adversary, not a bound.

**Expert:** And the payload advice?

**Me:** That's the weakest part right now. `info` suggests 0.05 bits per pixel or per non-zero AC coefficient, linear in the cover size. The **square root law** (Ker, Pevný, Kodovský and Fridrich; Filler, Ker and Fridrich) says secure capacity grows like √n, so a linear rule is too generous for big covers. It's also blind to texture. At 0.2 bits per non-zero AC coefficient, SRNet's P_E runs from 0.002 for the smoothest tenth of BOSSbase to 0.18 for the busiest quarter. Bits per non-zero AC coefficient doesn't put covers on an equal footing. The plan is to make the suggestion scale with √n and with a texture measure, calibrated on the light-payload SRNet runs now training.

**Expert:** Pooled steganalysis?

**Me:** Not something any single-image tool can fix. Ker's batch result means a warden who sees everything one person sends can combine weak per-image evidence into near certainty. The threat model says so: send as few images as the messages need. Traffic patterns are the same problem one level up: original-size photos sent as files, to the same recipient, again and again.

**Expert:** What about non-additive costs? Synchronizing changes between neighbours?

**Me:** Not done. CMD and Synch-style schemes that make adjacent changes agree in sign beat additive HILL against SRM, and it's an open question how much of that survives against SRNet. Before that comes the ternary coder. ScatterSteg has an extra wrinkle there: its binary coder plus value swaps keep the first-order histogram exactly, and a ternary coder gives most of that up. Which matters more against a CNN is an empirical question.

**Expert:** Side information?

**Me:** Not available. Side-informed JPEG schemes (SI-UNIWARD and the like) need the uncompressed precover, which a user who starts from a camera JPEG doesn't have. That's a real handicap compared with the published state of the art, and it's inherent to the use case.

**Expert:** Then the part people forget: the container.

**Me:** It's where tools tend to fail first. A file rewritten by libpng with default settings, or by libjpeg with standard Huffman tables, says "processed by a program" before anyone runs a detector. ScatterSteg reproduces the cover's PNG filters, IDAT chunking and zlib parameters, which it finds by trying settings until it gets the cover's own bytes back. It keeps a camera JPEG's header byte for byte and codes with its Huffman tables. 85 of 89 camera files come back byte-identical when saved without a message. What's left: progressive scan scripts from encoders other than libjpeg, and a few encoder quirks like fill bytes and padding bits. And metadata stays, so the output looks like the same file. If that metadata identifies you, that's your problem, not the tool's.

**Expert:** So where does it actually stand?

**Me:** Honestly: well engineered, cryptographically conventional, steganographically mid-pack. Content-adaptive costs, near-optimal binary coding, no cost-blind changes, careful file structure. Behind the state of the art in its coder (binary, not ternary), its costs (additive, not synchronized) and its payload guidance (linear, not √n). Not independently reviewed. Against a capable warden who trains on its output, only small messages in private, textured covers have a good chance. The remaining work is mostly closing those gaps and measuring each step, and then freezing the format so someone independent can try to break it.

---

*Numbers here come from [`benchmark/README.md`](benchmark/README.md) and [`THREAT_MODEL.md`](THREAT_MODEL.md), which give the methods and limitations; [`FORMAT.md`](FORMAT.md) specifies the format exactly.*
