## ElGamal
ElGamal encryption is a public-key encryption scheme that is based on the difficulty of finding discrete logarithms. It is less commonly used as it is less secure than other methods, and is vulnerable to chosen ciphertext attacks. It does however have some interesting properties, such as multiplicative homomorphism.

The elliptic curve variant of ElGamal encryption uses elliptic curve cryptography (ECC) instead of the traditional integer-based modular arithmetic used in the original scheme.

One advantage of the elliptic curve variant of ElGamal encryption is that it is more efficient than the original scheme, due to the faster point operations in ECC. It is also more secure, since the underlying elliptic curve is more difficult to break than modular arithmetic. However, the security of the elliptic curve variant of ElGamal encryption depends on the choice of the elliptic curve and the size of the key, so it is important to carefully select these parameters to ensure the desired level of security.

## Key Generation
To generate a key, first select a random number for the secret key $s$. The public key $P$ is calculated by multiplying the secret key by our curve's generator point.

$$ P = s \cdot G $$

## Encryption
ElGamal encryption can only encrypt messages that are valid points on the elliptic curve. Later in this document we will describe a mechanism to embed an arbitrary integer inside of a curve point to create a more practical encryption scheme. We are going to encrypt some point $M$ using public key $P$. The ciphertext in ElGamal is actually two curve points, denoted as $C_1$ and $C_2$. First, we must generate some random scalar $r$. We can then encrypt the point using the function below.

$$ \mathrm{enc_{P}}(M) = (C_1, C_2)= (r \cdot G, r \cdot P + M) $$

## Decryption
To recover the encrypted point using the secret key, use the below function.

$$ \mathrm{dec_{s}}(C_1, C_2) = C_2 - s \cdot C_1 $$

## How it Works
We can actually show that ElGamal decryption is in fact the inverse of encryption with simple algebra.

$$ \mathrm{dec_{s}}(\mathrm{enc_{P}}(M)) = (r \cdot P + M) - (s \cdot r \cdot G) = (r \cdot s \cdot G + M) - (s \cdot r \cdot G) = M $$

So now we have some intuition as to how recovering the original point works. However, how is secrecy preserved? This property relies on something called the discrete log problem for elliptical curves. We will only discuss the discrete log problem for elliptical curves here, but it originally is used in the context of prime fields.

The discrete log problem (for elliptical curves) is to find some scalar $k$ such that multiplying point $P$ times $k$ yields point $Q$.

$$ P \cdot k = Q $$

It turns out that given $P$ and $Q$, finding $k$ is extremely difficult.

If we take a look at our $\mathrm{enc}$ function, you can see that even though our adversaries know $C_1$ and $G$, it will still be computationally difficult to recover $r$. Since $r$ cannot be recovered, there is no way to subtract $r \cdot P$ from $C_2$ to yield $M$.

Fortunately for the receiver of the message, $r \cdot P$ can easily be recovered by multiplying the secret key $s$ by $C_1$. Given that $C_2$ is just equal to $r \cdot P + M$, we just need to subtract our recovered $r \cdot P$ from $C_2$ to yield the original message $M$.

## Encrypting Arbitrary Messages
We noted earlier that the message $M$ to be encrypted must be a valid point on the curve. However, we often want to send messages that contain arbitrary data. To do this, we need a way to convert any integer $n$ into a curve point $P$. This method is based on [this paper](https://arxiv.org/pdf/1707.04892.pdf) by Ahmad Steef, A. Alkhatib, and M. N. Shamma. It is actually quite simple.

Select some integer value $k$. The larger $k$ is, the greater the likelyhood we can find a good embedding for $n$. However, as $k$ increases in size, the maximum size $n$ that can be embedded in a single point decreases.

To calculate the x value of our point, use the below equation with $i$ starting at 0.

$$ x = k \cdot n + i $$

Then, attempt to calculate the $y$ coordinate on the curve that corresponds to the $x$ coordinate. This may not be possible since not every $x$ value is on the curve. If there is no valid $y$, simply increment $i$ and try again.

To recover the message $n$ from the point's $x$ coordinate, use the equation below.

$$ n = \frac{x}{k} $$

As long as $i < k$, this method should decode the correct message. If $i \geq k$, then it is impossible to differentiate between $n$ and $n + 1$. This is why increasing the size of $k$ lowers the failure rate.
