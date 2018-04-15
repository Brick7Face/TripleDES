import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

import java.io.PrintStream;
import java.io.FileOutputStream;
import java.io.FileDescriptor;

public class TestRunner {
   public static void main(String[] args) {
      Result result = JUnitCore.runClasses(TestTripleDES.class);
		
      for (Failure failure : result.getFailures()) {
		 System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out)));
         System.out.println(failure.toString() + " --FAIL");
      }
   }
}  	