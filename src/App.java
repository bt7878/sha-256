final class SHA256 {
    private SHA256() {
        throw new AssertionError();
    }

    public static byte[] hash(byte[] toHash) {
        byte input[] = pad(toHash);

        int k[] = new int[] { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
                0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
                0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc,
                0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351,
                0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
                0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585,
                0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
                0xc67178f2 };

        int h0 = 0x6a09e667;
        int h1 = 0xbb67ae85;
        int h2 = 0x3c6ef372;
        int h3 = 0xa54ff53a;
        int h4 = 0x510e527f;
        int h5 = 0x9b05688c;
        int h6 = 0x1f83d9ab;
        int h7 = 0x5be0cd19;

        // preallocate message schedule to save on allocations
        int w[] = new int[64];

        // break into 512 bit chunks
        for (int i = 0; i < input.length; i += 64) {
            createMsgSchedule(w, input, i);

            int a = h0;
            int b = h1;
            int c = h2;
            int d = h3;
            int e = h4;
            int f = h5;
            int g = h6;
            int h = h7;

            for (int j = 0; j < 64; j++) {
                int S1 = Integer.rotateRight(e, 6) ^ Integer.rotateRight(e, 11) ^ Integer.rotateRight(e, 25);
                int ch = e & f ^ ~e & g;
                int temp1 = h + S1 + ch + k[j] + w[j];
                int S0 = Integer.rotateRight(a, 2) ^ Integer.rotateRight(a, 13) ^ Integer.rotateRight(a, 22);
                int maj = a & b ^ a & c ^ b & c;
                int temp2 = S0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
            h5 += f;
            h6 += g;
            h7 += h;
        }

        byte out[] = new byte[32];
        for (int i = 3; i >= 0; i--) {
            out[i] = (byte) (h0 >>> 8 * (3 - i) & 0xff);
            out[4 + i] = (byte) (h1 >>> 8 * (3 - i) & 0xff);
            out[8 + i] = (byte) (h2 >>> 8 * (3 - i) & 0xff);
            out[12 + i] = (byte) (h3 >>> 8 * (3 - i) & 0xff);
            out[16 + i] = (byte) (h4 >>> 8 * (3 - i) & 0xff);
            out[20 + i] = (byte) (h5 >>> 8 * (3 - i) & 0xff);
            out[24 + i] = (byte) (h6 >>> 8 * (3 - i) & 0xff);
            out[28 + i] = (byte) (h7 >>> 8 * (3 - i) & 0xff);
        }

        return out;
    }

    private static byte[] pad(byte[] toHash) {
        // Create an input data buffer who's size is the smallest multiple of 512 bits
        // that fits the input data + 65 bits
        byte padded[] = new byte[((toHash.length * 8 + 65 - 1) / 512 + 1) * 512 / 8];

        System.arraycopy(toHash, 0, padded, 0, toHash.length);
        padded[toHash.length] = (byte) 0x80;

        // append the size as big endian
        int size = toHash.length * 8;
        for (int i = 7; i >= 0; i--) {
            padded[padded.length - 8 + i] = (byte) (size & 0xff);
            size = size >>> 8;
        }

        return padded;
    }

    private static void createMsgSchedule(int[] intArr, byte[] bytes, int start) {
        for (int i = 0; i < 16; i++) {
            intArr[i] = bytes[i * 4 + start] << 24 & 0xff000000 | bytes[i * 4 + 1 + start] << 16 & 0x00ff0000
                    | bytes[i * 4 + 2 + start] << 8 & 0x0000ff00
                    | bytes[i * 4 + 3 + start] & 0x000000ff;
        }
        for (int i = 16; i < 64; i++) {
            int s0 = Integer.rotateRight(intArr[i - 15], 7) ^ Integer.rotateRight(intArr[i - 15], 18)
                    ^ intArr[i - 15] >>> 3;
            int s1 = Integer.rotateRight(intArr[i - 2], 17) ^ Integer.rotateRight(intArr[i - 2], 19)
                    ^ intArr[i - 2] >>> 10;
            intArr[i] = intArr[i - 16] + s0 + intArr[i - 7] + s1;
        }
    }

    public static String byteArrayToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes)
            hex.append(String.format("%02x", b));
        return hex.toString();
    }
}

public class App {
    public static void main(String[] args) throws Exception {
        byte hashed[] = SHA256.hash("hello world".getBytes());
        System.out.println(SHA256.byteArrayToHex(hashed));
    }
}
