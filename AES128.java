/**
 * AES-128 Algorithm
 */
import java.util.*;
import java.io.*;
public class AES128 {
  public static int[][] state=new int[4][4];// state matrix
  public static int[][] key=new int[4][4];// key matrix
  public static int[][][] allkey=new int[11][4][4];// a 3D array used to store all keys
  public static final int[] RCON={0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};// for key expansion
  public static final int[][] MIX={
    {0x02,0x03,0x01,0x01},
    {0x01,0x02,0x03,0x01},
    {0x01,0x01,0x02,0x03},
    {0x03,0x01,0x01,0x02}
  };// mix-col matrix
  public static final int[][] INVMIX={
    {0x0e,0x0b,0x0d,0x09},
    {0x09,0x0e,0x0b,0x0d},
    {0x0d,0x09,0x0e,0x0b},
    {0x0b,0x0d,0x09,0x0e}
  };// inv mix-col matrix
  public static final int[][] SBOX={
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
  };// s-box
  public static final int[][] INVSBOX={
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
  };// inv s-box
  
  // main()
  // main function
  public static void main(String[] args) {
    readFile("test1plaintext.txt","test1key.txt");// read in .txt file, args[0] is plain text, and args[1] is key text
    keySchedule();// print plain text, source key, and all expanded keys
    encrypt();// encrypt
    System.out.println("");
    decrypt();// decrypt
    System.out.println("\n"+"End of Processing");
  }
  
  // keySchedule()
  // print plain text, source key, and all expanded keys
  public static void keySchedule(){
    // print plain text in one line
    System.out.println("Plaintext:");
    for(int n=0;n<4;n++){
        for(int m=0;m<4;m++){
          System.out.print(String.format("%02x",state[m][n]));
        }
    }
    // print key text in one line
    System.out.println("\n"+"Key:");
    for(int n=0;n<4;n++){
        for(int m=0;m<4;m++){
          System.out.print(String.format("%02x",key[m][n]));
        }
    }
    // print all expanded keys
    System.out.println("\n"+"Key Schedule:");
    int[][] tempkey=key;
    allkey[0]=tempkey;
    for(int i=1;i<11;i++){
      tempkey=KeyExpansion(tempkey,RCON[i-1]);// expand key
      allkey[i]=tempkey;// store one expanded key
    }
    for(int i=0;i<11;i++){
      for(int n=0;n<4;n++){
        for(int m=0;m<4;m++){
          System.out.print(String.format("%02x",allkey[i][m][n]));
          System.out.print("");
        }
        System.out.print(",");
      }
      System.out.println("");
    }
  }
  
  // encrypt()
  // encrypt texts
  public static void encrypt(){
    System.out.println("\n"+"ENCRYPTION PROCESS:");
    System.out.println("-----------------------");
    System.out.println("Plain Text:");
    for(int n=0;n<4;n++){
        for(int m=0;m<4;m++){
          System.out.print(String.format("%02x",state[m][n]));
          System.out.print("  ");
        }
        System.out.print("    ");
    }
    System.out.println("");
    state=xorMatrix(state,allkey[0]);// xor round key
    for(int r=1;r<=10;r++){
      state=SubBytes(state);// sub bytes
      state=ShiftRows(state);// shift rows
      if(r<=9){
        state=MixColumns(state);// mix col
        System.out.println("\n"+"State after call "+r+" to MixColumns()");
        System.out.println("---------------------------------------");
        printText(state);
      }
      state=xorMatrix(state,allkey[r]);// xor round key
    }
    System.out.println("\n"+"Cipher Text:");
    printText(state);
  }
  
  // decrypt
  // decrypt texts
  public static void decrypt(){
    System.out.println("\n"+"DECRYPTION PROCESS:");
    System.out.println("-----------------------");
    System.out.println("Cipher Text:");
    printText(state);
    state=xorMatrix(state,allkey[10]);// xor round key (inverse)
    for(int r=9;r>=1;r--){
      state=InvShiftRows(state);// inv shift rows
      state=InvSubBytes(state);// inv sub bytes
      state=xorMatrix(state,allkey[r]);// xor round key (inverse)
      state=InvMixColumns(state);// inv mix col
      System.out.println("\n"+"State after call "+(10-r)+" to InvMixColumns()");
      System.out.println("---------------------------------------");
      printText(state);
    }
    state=InvShiftRows(state);// inv shift rows
    state=InvSubBytes(state);// inv sub bytes
    state=xorMatrix(state,allkey[0]);// xor round key (inverse)
    System.out.println("\n"+"Plain Text:");
    printText(state);
  }
  
  // printText()
  // print one line plain, key, or cipher text
  public static void printText(int[][] s){
    for(int n=0;n<4;n++){
        for(int m=0;m<4;m++){
          System.out.print(String.format("%02x",s[m][n]));// we use int to store data, but we only need 1 byte/8 bits. So, we only show 1 byte for our int data
          System.out.print("  ");
        }
        System.out.print("    ");
    }
    System.out.println("");
  }
  
  // xorMatrix()
  // make xor between two 4x4 matrices
  public static int[][] xorMatrix(int[][] s,int[][] k){
    int[][] result=new int[4][4];
    for(int m=0;m<4;m++){
      for(int n=0;n<4;n++){
        result[m][n]=s[m][n]^k[m][n];// xor each pair of elements
      }
    }
    return result;
  }
  
  // MixColumns()
  // mix-col for aes
  public static int[][] MixColumns(int[][] s){
    int[] temp;
    int result[][]=new int[4][4];
    for(int i=0;i<4;i++){
      temp=pickCol(s,i);// pick one col from state
      temp=multMatrix(MIX,temp);// mult in GF(2^8)
      result[0][i]=temp[0];
      result[1][i]=temp[1];
      result[2][i]=temp[2];
      result[3][i]=temp[3];// store 
    }
    return result;
  }
  
  // InvMixColumns()
  // inv mix-col for aes
  public static int[][] InvMixColumns(int[][] s){
    int[] temp;
    int[][] result=new int[4][4];
    for(int i=0;i<4;i++){
      temp=pickCol(s,i);// pick one col from state
      temp=multMatrix(INVMIX,temp);// mult in GF(2^8)
      result[0][i]=temp[0];
      result[1][i]=temp[1];
      result[2][i]=temp[2];
      result[3][i]=temp[3];// store  
    }
    return result;
  }
  
  // multMatrix()
  // mult one column with mix/invmix matrix in GF(2^8)
  public static int[] multMatrix(int[][] m,int[] c){
    int[] result=new int[4];
    for(int i=0;i<4;i++){
      result[i]=multGF(m[i][0],c[0])^multGF(m[i][1],c[1])^multGF(m[i][2],c[2])^multGF(m[i][3],c[3]);
    }// mult one col from state with mix/invmix matrix in GF(2^8)
    return result;
  }
  
  // readFile()
  // read input files
  public static void readFile(String plaintext,String keytext){
    BufferedReader br=null;
    String line=null;
    String[] tokens=null;
    //read plain text file
    try{
      br=new BufferedReader(new FileReader(plaintext));
      line=br.readLine();
      tokens=line.split(" ");
      int i=0;
      for(int n=0;n<4;n++){
        for(int m=0;m<4;m++){
            state[m][n]=Integer.parseInt(tokens[i],16);// store file-in data
            i++;
        }
      }
    }catch(IOException ioe){
      ioe.printStackTrace();
    }
    //read key text file
    try{
      br=new BufferedReader(new FileReader(keytext));
      line=br.readLine();
      tokens=line.split(" ");
      int i=0;
      for(int n=0;n<4;n++){
        for(int m=0;m<4;m++){
            key[m][n]=Integer.parseInt(tokens[i],16);// store file-in data
            i++;
        }
      }
    }catch(IOException ioe){
      ioe.printStackTrace();
    }
  }
  
  // SubBytes()
  // sub bytes for aes
  public static int[][] SubBytes(int[][] s){
    int temp=0;
    int high=0;
    int low=0;
    for(int m=0;m<4;m++){
      for(int n=0;n<4;n++){
        temp=s[m][n];// get one element {xy}
        high=(temp>>4) & 0xf;// get x
        low=temp & 0xf;// get y
        s[m][n]=SBOX[high][low];// replace
      }
    }
    return s;
  }
  
  // InvSubBytes()
  // inv sub bytes for aes
  public static int[][] InvSubBytes(int[][] s){
    int temp=0;
    int high=0;
    int low=0;
    for(int m=0;m<4;m++){
      for(int n=0;n<4;n++){
        temp=s[m][n];// get one element {xy}
        high=(temp>>4) & 0xf;// get x
        low=temp & 0xf;// get y
        s[m][n]=INVSBOX[high][low];// replace
      }
    }
    return s;
  }
  
  // ShiftRows()
  // shift rows for aes
  public static int[][] ShiftRows(int[][] s){
    for(int i=0;i<4;i++){
      s[i]=shiftLeft(s[i],i);
    }// left shift i times for the i th row
    return s;
  }
  
  // shiftLeft()
  // left shift one line for n times, it's a helper for ShiftRows()
  public static int[] shiftLeft(int[] row,int times){
    if(times%4 == 0){
      return row;
    }else{
      while(times>0){
        int temp=row[0];
        for(int i=0;i<row.length-1;i++){
          row[i]=row[i+1];
        }
        row[row.length-1]=temp;
        times--;
      }
      return row;
    }
  }
  
  // InvShiftRows()
  // inv shift rows for aes
  public static int[][] InvShiftRows(int[][] s){
    for(int i=0;i<4;i++){
      s[i]=shiftRight(s[i],i);
    }// right shift i times for the i th row
    return s;
  }
  
  // shiftRight()
  // right shift one line for n times, it's a helper for InvShiftRows()
  public static int[] shiftRight(int[] row,int times){
    if(times%4 == 0){
      return row;
    }else{
      while(times>0){
        int temp=row[row.length-1];
        for(int i=row.length-1;i>0;i--){
          row[i]=row[i-1];
        }
        row[0]=temp;
        times--;
      }
      return row;
    }
  }
  
  // KeyExpansion()
  // expand key, 1 source key to 11 keys
  public static int[][] KeyExpansion(int[][] k,int rcon){
    int[] temp;
    int[] preCol=pickCol(k,3);// get previous col
    int[][] result=new int[4][4];
    for(int i=0;i<4;i++){
      temp=pickCol(k,i);// get the pair col in previous matrix
      if(i==0){// for the first col
        rotWord(preCol);// rotate previous col
        preCol=subColBytes(preCol);// sub
        preCol=xorCol(temp,preCol);// xor
        preCol[0]=preCol[0]^rcon;// xor with rcon
      }else{// for other cols
        preCol=xorCol(temp,preCol);// just xor
      }
      for(int m=0;m<4;m++){
        result[m][i]=preCol[m];
      }// store
    }
    return result;
  }
  
  // pickCol()
  // pick one col in a matrix
  public static int[] pickCol(int[][] k,int n){
    int[] result=new int[4];
    for(int i=0;i<4;i++){
      result[i]=k[i][n];
    }
    return result;
  }
  
  // rotWord()
  // rotate word in one column for expanding key
  public static void rotWord(int[] col){
    int temp=col[0];
    for(int i=0;i<col.length-1;i++){
      col[i]=col[i+1];
    }
    col[col.length-1]=temp;
  }
  
  // xorCol()
  // xor two columns
  public static int[] xorCol(int[] a,int[] b){
    int[] result=new int[4];
    for(int i=0;i<4;i++){
      result[i]=a[i]^b[i];
    }
    return result;
  }
  
  // subColBytes()
  // do sub bytes for one column (similar to SubBytes())
  public static int[] subColBytes(int[] col){
    int temp=0;
    int high=0;
    int low=0;
      for(int i=0;i<4;i++){
        temp=col[i];
        high=(temp>>4) & 0xf;
        low=temp & 0xf;
        col[i]=SBOX[high][low];
      }
    return col;
  }
  
  // multGF()
  // mult two numbers under GF(2^8)
  public static int multGF(int ver,int num){
    int result=-42;// a magic number for showing error (when cannot calculate)
    if(ver==0x01){
      result=mult01GF(num);
    }else if(ver==0x02){
      result=mult02GF(num);
    }else if(ver==0x03){
      result=mult03GF(num);
    }else if(ver==0x04){
      result=mult04GF(num);
    }else if(ver==0x08){
      result=mult08GF(num);
    }else if(ver==0x09){
      result=mult09GF(num);
    }else if(ver==0x0b){
      result=mult0bGF(num);
    }else if(ver==0x0d){
      result=mult0dGF(num);
    }else if(ver==0x0e){
      result=mult0eGF(num);
    }else{
      System.out.println("multiplication in GF(2^8) is failed!");
      System.out.println("");
    }
    return result;
  }
  
  // the following methods are different situations when calculate mult under GF(2^8)
  // mult01GF()
  public static int mult01GF(int num){
    return num;
  }
  // mult02GF()
  public static int mult02GF(int num){
    int high=num>>7;
    if((high & 1) == 0){
      return num<<1;
    }else{
      num=(num<<1)&0xff;
      num=num^0x1b;
      return num;
    }
  }
  // mult03GF()
  public static int mult03GF(int num){
    return mult02GF(num)^mult01GF(num);
  }
  // mult04GF()
  public static int mult04GF(int num){
    return mult02GF(mult02GF(num));
  }
  // mult08GF()
  public static int mult08GF(int num){
    return mult02GF(mult04GF(num));
  }
  // mult09GF()
  public static int mult09GF(int num){
    return mult08GF(num)^mult01GF(num);
  }
  // mult0bGF()
  public static int mult0bGF(int num){
    return mult08GF(num)^mult02GF(num)^mult01GF(num);
  }
  // mult0dGF()
  public static int mult0dGF(int num){
    return mult08GF(num)^mult04GF(num)^mult01GF(num);
  }
  // mult0eGF()
  public static int mult0eGF(int num){
    return mult08GF(num)^mult04GF(num)^mult02GF(num);
  }
  
}

