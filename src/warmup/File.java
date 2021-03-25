package warmup;
class File{
  private String name;
  private String data;

  public File(String name,String data){
    this.name = name;
    this.data = data;
  }

  //used in output
  public String getName(){
    return this.name;
  }

  //the String that you need to scan.
  public String getData(){
    return this.data;
  }
}