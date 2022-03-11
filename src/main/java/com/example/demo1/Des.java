package com.example.demo1;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Random;

public class Des {

    int[] leftShiftsNumber = new int[]{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
    private static final byte[] staticHexCharLookup = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    private static final char[] staticBinCharLookup = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    byte[][] key; //Stores calculated keys


    private String convertStringToHex(String str) {
        StringBuilder stringBuilder = new StringBuilder();
        char[] charArray = str.toCharArray();
        for (char c : charArray) {
            String charToHex = Integer.toHexString(c);
            stringBuilder.append(charToHex);
        }
        return stringBuilder.toString();
    }

    private String convertHexToString(String hex) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hex.length(); i+=2) {
            String str = hex.substring(i, i+2);
            output.append((char)Integer.parseInt(str, 16));
        }
        return output.toString();
    }

    public String generateKey(int length)
    {
        char[] chars = "abcdefghijklmnopqrstuvwxyz1234567890".toCharArray();

        StringBuilder sb = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < length; i++) {
            char c = chars[random.nextInt(chars.length)];
            sb.append(c);
        }
        return sb.toString();
    }

    //Encrypts hex string
    public String encrypt(String message, String keyString) {
        String messageHex = convertStringToHex(message);
        String keyHex = convertStringToHex(keyString);

        calculateKeys(keyHex);

        byte[] inputBlock = hexBlockToByteArray(messageHex);
        byte[] perInput = permutInput(DesTables.IP, inputBlock);
        byte[] L = Arrays.copyOfRange(perInput, 0, 32);
        byte[] R = Arrays.copyOfRange(perInput, 32, 64);
        for (int i = 0; i < 16; i++) {
            byte[] tempR = Arrays.copyOfRange(R, 0, 32);
            byte[] currKey = key[i];
            byte[] fByte = f(R, currKey);
            byte[] lXorF = xorBitArray(L, fByte);

            //Switch parts (32 bits)
            L = tempR;
            R = lXorF;
        }
        byte[] outputBit = concatArrays(R, L);
        byte[] outputBitPerm = permutInput(DesTables.FP, outputBit);
        String encMessage = bitsToHexString3(outputBitPerm);
        return encMessage;
    }

    //Decrytps hex string
    public String decrypt(String message, String keyString) {
        String keyHex = convertStringToHex(keyString);

        calculateKeys(keyHex);
        byte[] inputBlock = hexBlockToByteArray(message);
        byte[] perInput = permutInput(DesTables.IP, inputBlock);

        byte[] L = Arrays.copyOfRange(perInput, 0, 32);
        byte[] R = Arrays.copyOfRange(perInput, 32, 64);
        for (int i = 15; i >= 0; i--) {
            byte[] tempR = Arrays.copyOfRange(R, 0, R.length);
            byte[] currKey = key[i];
            byte[] fByte = f(R, currKey);
            byte[] lXorF = xorBitArray(L, fByte);

            //Switch parts (32 bits)
            L = tempR;
            R = lXorF;
        }
        byte[] outputBit = concatArrays(R, L);
        byte[] outputBitPerm = permutInput(DesTables.FP, outputBit);
        String encMessage = bitsToHexString3(outputBitPerm);
        return convertHexToString(encMessage);
    }

    //Calculates all keys for DES for one given start key
    private void calculateKeys(String keyStr) {
        key = new byte[16][48];
        byte[] k = hexBlockToByteArray(keyStr);
        byte[] permutedKey = permutInput(DesTables.PC1, k);

        byte[] currC0 = Arrays.copyOfRange(permutedKey, 0, 28); // Left part of permuted key
        byte[] currD0 = Arrays.copyOfRange(permutedKey, 28, 56); // Right part of permuted key
        byte[] currC = currC0;
        byte[] currD = currD0;
        byte[] kPc2;
        for (int i = 0; i < 16; i++) {
            currC = shiftKey(currC, leftShiftsNumber[i]);
            currD = shiftKey(currD, leftShiftsNumber[i]);
            kPc2 = concatArrays(currC, currD);
            kPc2 = permutInput(DesTables.PC2, kPc2);
            key[i] = kPc2;
        }
    }

    //Concat arraqs into new one array. Firstly it adds from arr1, next from arr2.
    private byte[] concatArrays(byte[] arr1, byte[] arr2) {
        int arr1length = arr1.length;
        int arr2length = arr2.length;
        byte[] concArr = new byte[arr1length + arr2length];
        System.arraycopy(arr1, 0, concArr, 0, arr1length);
        System.arraycopy(arr2, 0, concArr, arr1length, arr2length);

        return concArr;
    }

    //Convert given string to the array of bytes ( bits ) For ex. 16 chars = 16 * 4 bytes ( bits) = 64 bits
    private byte[] hexBlockToByteArray(String hexBlock) {
        byte[] inputBlockBit = new byte[64];
        for (int i = 0; i < hexBlock.length(); i++) {
            byte b = hexCharToByte(hexBlock.charAt(i));
            int inputBlockBitPos = i * 4 + 3;
            for (int pos = 0; pos < 4; pos++) {
                byte singleBit = getBit(b, pos);
                inputBlockBit[inputBlockBitPos] = singleBit;
                inputBlockBitPos--;
            }

        }

        return inputBlockBit;
    }

    //left shift key
    private byte[] shiftKey(byte[] key, int shiftNumber) {
        byte b1 = key[0];
        byte b2 = key[1];

        int keyLength = key.length;
        if (shiftNumber == 2) {
            for (int i = 0; i < key.length - 2; i++) {
                key[i] = key[i + 2];
            }

            key[keyLength - 2] = b1;
            key[keyLength - 1] = b2;
        } else {
            for (int i = 0; i < key.length - 1; i++) {
                key[i] = key[i + 1];
            }

            key[keyLength - 1] = b1;
        }
        return key;
    }

    /*
    Get single bit of given byte. Right shifts given byte by pos and perform AND operation.
     */
    private byte getBit(byte inputValue, int position) {
        byte shiftedByte = (byte) (inputValue >> position);
        return (byte) (shiftedByte & 1);
    }

    /*
    Permut inputBlockBit with given permutPosition array
     */
    private byte[] permutInput(byte[] permutPosition, byte[] inputBlockBit) {
        byte[] permutedBockBit = new byte[permutPosition.length];
        for (int i = 0; i < permutPosition.length; i++) {
            byte currPos = permutPosition[i];
            permutedBockBit[i] = inputBlockBit[currPos - 1]; //currPos -1 cause pos are from 1-64
        }
        return permutedBockBit;
    }

    private byte[] f(byte[] R, byte[] K) {
        byte[] r = permutInput(DesTables.E, R); //Extends input 32bit to 48 bit
        byte[] xorArr = xorBitArray(r, K);

        byte[] sBoxOutputBit = new byte[32];
        int currSBoxStartIndex;
        int currSBoxEndIndex;
        int sBoxOutputBitStartIndex;
        int sBoxOutputBitEndIndex;
        for (int i = 0; i < 8; i++) {
            currSBoxStartIndex = i * 6;
            currSBoxEndIndex = (i + 1) * 6;
            byte[] currSBoxInput = Arrays.copyOfRange(xorArr, currSBoxStartIndex, currSBoxEndIndex);
            byte[] singleBoxOutput = sBoxValue(currSBoxInput, i); // 4 bits

            sBoxOutputBitStartIndex = i * 4; //4 indexes - 4 bits from single sbox
            sBoxOutputBitEndIndex = (i + 1) * 4;
            setElements(sBoxOutputBit, singleBoxOutput, sBoxOutputBitStartIndex, sBoxOutputBitEndIndex);
        }
        byte[] permuttedSBoxOutputBit = permutInput(DesTables.P, sBoxOutputBit);
        return permuttedSBoxOutputBit;
    }

    //Sets elements from arrToGet to arrToSet on indexes from start(inclusive) to end(exclusive)
    private void setElements(byte[] arrToSet, byte[] arrToGet, int startPos, int endPos) {

        int currPos = startPos;
        for (int j = 0; j < 4; j++) {
            byte elToSet = arrToGet[j];
            arrToSet[currPos] = elToSet;
            currPos++;
        }

    }

    /*
    Xores every byte of given array 1 with byte on same position from array 2
     */
    private byte[] xorBitArray(byte[] arr1, byte[] arr2) {
        if (arr1.length == arr2.length) {
            byte[] xorArr = new byte[arr1.length];
            for (int i = 0; i < arr1.length; i++) {
                xorArr[i] = (byte) (arr1[i] ^ arr2[i]);
            }
            return xorArr;
        } else {
            return null;
        }
    }

    /*
    Calculates single sbox value for given input bits (6 bits) and sboxnumber (0-7)
     */
    private byte[] sBoxValue(byte[] inputBits, int sBoxNumber) {
        byte[] arr = new byte[4];

        int[] rowPos = {0, 5};
        int[] colPos = {1, 2, 3, 4};
        String sBoxRowStr = bitsToString(inputBits, rowPos);
        String sBoxColStr = bitsToString(inputBits, colPos);
        int sBoxRow = Integer.parseInt(sBoxRowStr, 2);
        int sBoxCol = Integer.parseInt(sBoxColStr, 2);

        byte sBoxValue = DesTables.S[sBoxNumber][sBoxRow][sBoxCol];
        int arrPos = 3;
        for (int k = 0; k < 4; k++) {
            arr[arrPos] = getBit(sBoxValue, k); //TODO sprawdzic czy zapisuje bity w dobrej kolejnosci
            arrPos--;
        }

        return arr;
    }

    //Converts input bits from positions (from array pos) to String
    private String bitsToString(byte[] input, int[] pos) {
        String convBitsStr = "";
        int currPos, currPosVal;
        for (int i = 0; i < pos.length; i++) {
            currPos = pos[i];
            currPosVal = input[currPos];
            convBitsStr += Character.toString((char) (currPosVal + 48));
        }

        return convBitsStr;
    }

    //Converts input arr of bytes to String. Every byte of given array is represented as single bit. Every char of returned string is composed from 4 bytes(bits) combination.
    private String bitsToHexString3(byte[] input) {
        String hexStr = "";

        for (int i = 0; i < input.length / 4; i++) {
            byte startPos = (byte) (i * 4);
            byte b0 = input[startPos];
            byte b1 = input[startPos + 1];
            byte b2 = input[startPos + 2];
            byte b3 = input[startPos + 3];
            byte[] bitSet = new byte[]{b0, b1, b2, b3};
            String bitStr = Character.toString((char) (b0 + 48)) + Character.toString((char) (b1 + 48)) + Character.toString((char) (b2 + 48)) + Character.toString((char) (b3 + 48));
            int byteValue = Integer.parseInt(bitStr, 2);
            hexStr += intToHexChar(byteValue);
        }

        return hexStr;
    }

    //Return byte value of hex char
    private byte hexCharToByte(char hexC) {
        return staticHexCharLookup[Integer.parseInt(Character.toString(hexC), 16)];
    }

    //Return char represented as given int
    private char intToHexChar(int i) {
        return staticBinCharLookup[i];
    }
}
