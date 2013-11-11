import java.io.File;
import java.io.IOException;

import de.innosystec.unrar.Archive;
import de.innosystec.unrar.exception.RarException;


public class Main {
	
	public static void main(String[] args){
		testArchive("test1.rar");
	}
	
	private static void testArchive(String location){
		Archive archive;
		try {
			archive = new Archive(new File(location), "test");
			System.out.println(location);
			System.out.println(archive.isEncrypted() ? "encrypted" : "not encrypted");
			System.out.println(archive.isPasswordProtected() ? "password protected" : "unprotected");
			
			System.out.println("");
			archive.close();
		} catch (RarException | IOException e) {
			e.printStackTrace();
		}
	}
	
}
