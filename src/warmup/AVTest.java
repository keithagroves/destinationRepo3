package warmup;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import org.junit.runners.JUnit4;

import java.util.regex.*;


public class AVTest {
    final String CHARS = "qwertyuioplkjhgfdsazxcvbnm1234567890QWERTYUIOPLKJHGFDSAZXCVBNM";
    String generateRandomString(long length){
      String ans = "";
      while(length > 0){
        ans = ans + CHARS.charAt( (int) (Math.random() * ((CHARS.length()-1 - 0) + 1)) + 0);
        length --;
      }
      return ans;
    }
    
    int generateRandomInt(int min,int max){
      return (int) (Math.random() * ((max - min) + 1)) + min;
    }
    
    
    
    @Test
    public void checkSameFilesWithDifferentIntensitySettings() {
      AntiVirus AV = new AntiVirus();
      
      String[] intensity1signatures = new String[]{
        "malware",
        "virus",
        "infect"
      };
      
      String[] intensity2signatures = new String[]{
        "ransomware",
        "trojan",
        "trojanHorse",
        "worm",
        "spyware",
        "keystrokelogger",
        "adware",
        "botnet",
        "rootkit",
      };
      
      String[] intensity3signatures = new String[]{
        "DeleteSys32",
        "OverideMBR",
        "EncryptAll",
        "openrandomwebsite",
        "openrandwebsite",
        "sendalldata",
        "recordKeyboard",
        "recordmouse",
        "destroy",
        "overheat",
        "getfullcontrol",
        "uploadharddrive",
        "uploadharddisk",
        "overload",
        "changeOS",
        "encrypt",
        "changeDesktop",
        "ddos",
        "dos",
        "hide",
        "inject",
        "ransom",
        "getcreditcardinfo",
        "getpasswords",
        "getpass",
      };
      
      VirusDB DB = new VirusDB(intensity1signatures,intensity2signatures,intensity3signatures);
      
      File[] files = new File[4];
      
      files[0] = new File("file0","qmesMJq1EAjBLPclDJVil3kmP3Bgj5qocZQnQuK0rGffyHvMCY");
      files[1] = new File("file1","1OipRqMWEaZlviruse48XKWO2VLz40YMiC9x7FlUOsjg9");
      files[2] = new File("file2","q4khFPhsPyWareRbxFZefTpN74cRr8Rh9b18Gtvbyz3");
      files[3] = new File("file3","ICqMYeVk6OoAIcI1dGl36AfKH1qyn2VywRjqxMVu6PFeuZyoaxdpaldPAdsdasGeTpASsReRdc");
      
      //defualt scanIntensity should be 0 - off so everything is safe.
      assertEquals("file0 is safe",AV.scanFile(files[0],DB));
      assertEquals("file1 is safe",AV.scanFile(files[1],DB));
      assertEquals("file2 is safe",AV.scanFile(files[2],DB));
      assertEquals("file3 is safe",AV.scanFile(files[3],DB));
      
      AV.setScanIntensity(1);
      assertEquals("file0 is safe",AV.scanFile(files[0],DB));
      assertEquals("file1 is not safe",AV.scanFile(files[1],DB));
      assertEquals("file2 is safe",AV.scanFile(files[2],DB));
      assertEquals("file3 is safe",AV.scanFile(files[3],DB));
      
      AV.setScanIntensity(2);
      assertEquals("file0 is safe",AV.scanFile(files[0],DB));
      assertEquals("file1 is not safe",AV.scanFile(files[1],DB));
      assertEquals("file2 is not safe",AV.scanFile(files[2],DB));
      assertEquals("file3 is safe",AV.scanFile(files[3],DB));
      
      AV.setScanIntensity(3);
      assertEquals("file0 is safe",AV.scanFile(files[0],DB));
      assertEquals("file1 is not safe",AV.scanFile(files[1],DB));
      assertEquals("file2 is not safe",AV.scanFile(files[2],DB));
      assertEquals("file3 is not safe",AV.scanFile(files[3],DB));
           
    }
    
    @Test
    public void checkRandomFiles(){
      AntiVirus AV = new AntiVirus();
      
      String[] intensity1signatures = new String[]{
        "malware",
        "virus",
        "infect"
      };
      
      String[] intensity2signatures = new String[]{
        "ransomware",
        "trojan",
        "trojanHorse",
        "worm",
        "spyware",
        "keystrokelogger",
        "adware",
        "botnet",
        "rootkit",
      };
      
      String[] intensity3signatures = new String[]{
        "DeleteSys32",
        "OverideMBR",
        "EncryptAll",
        "openrandomwebsite",
        "openrandwebsite",
        "sendalldata",
        "recordKeyboard",
        "recordmouse",
        "destroy",
        "overheat",
        "getfullcontrol",
        "uploadharddrive",
        "uploadharddisk",
        "overload",
        "changeOS",
        "encrypt",
        "changeDesktop",
        "ddos",
        "dos",
        "hide",
        "inject",
        "ransom",
        "getcreditcardinfo",
        "getpasswords",
        "getpass",
      };
      
      VirusDB DB = new VirusDB(intensity1signatures,intensity2signatures,intensity3signatures);
      
      AntiVirusSolution Checker = new AntiVirusSolution();
      
      for(int i = 0;i<100000;i++){
        int scanIntensity = generateRandomInt(1,3);
        AV.setScanIntensity(scanIntensity);
        Checker.setScanIntensity(scanIntensity);
        File file = new File(generateRandomString(generateRandomInt(5,10)),generateRandomString(generateRandomInt(10,50)));
        assertEquals(Checker.scanFile(file,DB), AV.scanFile(file,DB));
      }
    }
    
}

//This is used to check the random cases.
//This is my solution that I copy,pasted in the tests.
//This should never be given in the Example Test Cases.
class AntiVirusSolution{
  
  private int scanIntensity = 0;
  
  //this method is ready for you.
  public void setScanIntensity(int level){
    scanIntensity = level;
  }
  
  //write this method.
  public String scanFile(File file,VirusDB database){
    if(scanIntensity >=1){      
      for(int i = 0;i<database.getSignatures(1).length;i++){
        Matcher m = Pattern.compile(database.getSignatures(1)[i],Pattern.CASE_INSENSITIVE).matcher(file.getData());
        if(m.find()){
          return file.getName()+" is not safe";
        }        
      }
      if(scanIntensity >= 2){
        for(int i = 0;i<database.getSignatures(2).length;i++){
        Matcher m = Pattern.compile(database.getSignatures(2)[i],Pattern.CASE_INSENSITIVE).matcher(file.getData());
          if(m.find()){
            return file.getName()+" is not safe";
          }        
        }
        if(scanIntensity >= 3){
          for(int i = 0;i<database.getSignatures(3).length;i++){
          Matcher m = Pattern.compile(database.getSignatures(3)[i],Pattern.CASE_INSENSITIVE).matcher(file.getData());
            if(m.find()){
              return file.getName()+" is not safe";
            }        
          }
        }
      }
    }
    return file.getName()+" is safe";
    
  }
  
}