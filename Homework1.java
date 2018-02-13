import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Homework1 {
	// PARAMETERS
	// set all text to lower case to ignore upper cases
	private static  boolean setLowerCase = true;
	//multiclass or binary class. Values:
	// multiclass
	// binary
	private static String noClasses = "multiclass";
	// Size of the dataset
	private static  int datasetSize = 5000;
	// Portion of malware data samples	
	private static  double datasetRatio = 0.8;
	// Discard malware classes with less than a number of samples
	private static int minMalwareClassSize = 20;
	// Difference between number of occurrences of a feature in malware and safe apps
	// Percentage based on size of the dataset
	private static double datasetPct = 0.03;
	
	private static long thresholdFeatureFilter = Math.round(datasetSize*datasetPct);
	// List of features to use - if left empty it will use all of them
	private static List<String> forceFeatures = 
			//new ArrayList<String>();
			//new ArrayList<String>(Arrays.asList("api_call", "call", "permission", "real_permission", "url"));
			//new ArrayList<String>(Arrays.asList("real_permission"));
			new ArrayList<String>(Arrays.asList("api_call","real_permission"));

	
	// Add app hash to the binary classification file for further debugging
	private static boolean addAppHash = false;
	
	private static String debrinPath="/Users/JoseMa/Documents/drebin/feature_vectors/";
	private static String debrinFile="/Users/JoseMa/Documents/drebin/sha256_family.csv";
	
	// Classes with number of occurrences
	private static Map<String, Integer> malwareClasses= new HashMap<String, Integer>();
	private static Map<String, Integer> features= new HashMap<String, Integer>();

	private static Map<String, String> malwareApps= new HashMap<String, String>();
	private static Map<String, Integer> featureOccurrences= new HashMap<String, Integer>();
	
	//Full list of files
	private static List<String> fileList = new ArrayList<>();
	
	//List of files to read and their binary class malware/safe
	private static Map<String, String> dataSetFiles = new HashMap<String, String>();
	//File content for each map, with the hash as the key
	private static Map<String, String> dataFiles = new HashMap<String, String>();
	//List containing the 
	private static Map<String, String> dataSetClassified = new HashMap<String, String>();
	
	private static String outputFileWeka = "/Users/JoseMa/malwareDataFile_Weka_" +System.currentTimeMillis()+".csv"; 
	private static String outputFileBayes = "/Users/JoseMa/malwareDataFile_Bayes_" +System.currentTimeMillis()+".csv"; 
	
	
	public static void main(String[] args) {
		
		//Initialise full list of apps
		getFileList();
		
		// Get malware app list
		List<String> fullFile = new ArrayList<>(readLines(debrinFile));
		String classifiedData[] = new String[2];
		for (int l=1; l<fullFile.size(); l++){
			classifiedData = fullFile.get(l).split(",");
			malwareApps.put(classifiedData[0], classifiedData[1]);
			// Get most popular malware classes 
			malwareClasses.put(classifiedData[1], !malwareClasses.containsKey(classifiedData[1]) ? 1 : malwareClasses.get(classifiedData[1])+1);
			
		}
		
		List <String> malwareAppsList = new ArrayList<>(malwareApps.keySet());
		
		println("Number of apps in the dataset: " + fileList.size());
		println(" - Total dictionary malware apps: " + malwareApps.size());
		
		// Get list of safe apps
		
		//fileList.removeIf(a -> malwareAppsList.contains(a));
		/* for (Iterator<String> it = fileList.iterator(); it.hasNext();)
		        if (malwareAppsList.contains(it.next())) {
		            it.remove();
		        }*/
		// Remove malware hashes from the full list of files.
		fileList.removeIf(a -> malwareAppsList.contains(a));
		println(" - Total dictionary safe apps: " + fileList.size());
		println(" - Malware/Safe data sample ratio: " + datasetRatio);
		println(" - Total number of malware types: " + malwareClasses.size());
		
		//Remove any malware classes with the set number of samples
		Map<String, Integer> keepMalwareClasses = malwareClasses.entrySet().stream().filter(e ->e.getValue()>=minMalwareClassSize)
										  .collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue()));
		
		
		Map<String, String> malwareAppsReduced= new HashMap<String,String>();
		if (noClasses.contains("multiclass")){
		//Filter out any classes with low number of samples
			malwareAppsReduced= malwareApps.entrySet().stream().filter(e -> keepMalwareClasses.keySet().contains(e.getValue()))
					  .collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue()));;
			// If classifying malware, remove classes with low number of samples
		
			//malwareApps.values().removeIf(c -> keepMalwareClasses.containsKey(c));
			println(" - Malware classes with small number of samples: " + keepMalwareClasses.size());
			println(" - Number of apps to test: " + malwareAppsReduced.size());
		}else {
			println(" - Number of apps to test: " + malwareApps.size());
		}

		//println("Malware apps: " + malwareApps);
		
		/*********
		 * Get info for all apps
		 * Make a list of all the features in the app
		 * First check if there are features specified in forceFeatures
		 * If there are, filter out by keywords
		 * 
		 * Compare frequency of features between malware and safe apps
		 * It will update the map 'features with:
		 * - key = feature name
		 * - integer = number of common occurrences
		 * Value of the integer:
		 * 0 = same occurrences in safe and malware samples
		 * <0 = more occurrences in safe apps
		 * >0 = more occurrences in malware apps
		 * If value is very close to 0 it means it doesn't discriminate 
		 * Features can be filtered based on the variable thresholdFeatureFilter
		 * It will remove any features with abs(integer) < thresholdFeatureFilter
		 *
		 */
		
		
		
		Iterator<String> malwareAppsI;
		Iterator<String> safeAppsI = fileList.iterator();
		String appPath="";
		String fileName="";
		long malwareDataSize = 0;
		long safeDataSize = 0;
		/* Set the amount of data samples to add to the file
		 * If we are classifying the malware, we only get malware samples 
		 * and to a maximum of malware dictionary size
		 * If we are detecting malware, get 50/50 samples of malware and safe apps
		 */
		if (noClasses.equals("multiclass") ) {
			//Only evaluating malware classes with more than 'minMalwareClassSize' data samples
			malwareAppsI = malwareAppsReduced.keySet().iterator();
			malwareDataSize = (datasetSize > malwareAppsReduced.size()) ? malwareAppsReduced.size() : datasetSize;
			safeDataSize = 0;

		} else {
			malwareAppsI = malwareApps.keySet().iterator();			
			malwareDataSize = (Math.round(datasetSize*datasetRatio) > malwareApps.size()) ? malwareApps.size() : Math.round(datasetSize*datasetRatio);
			safeDataSize = (datasetSize - malwareDataSize > fileList.size()) ? fileList.size() : datasetSize - malwareDataSize;
		}
		println(" - Malware apps in the dataset: " + malwareDataSize);
		println(" - Safe apps in the dataset: " + safeDataSize);
		
		String feature = "";
		for(int m=0; m<malwareDataSize;m++){
			fileName = malwareAppsI.next();
			appPath = debrinPath+fileName;
			if (noClasses.equals("multiclass") ) {
				dataSetFiles.put(fileName, malwareApps.get(fileName));
			} else {
				dataSetFiles.put(fileName, "malware");
			}
			List<String> appInfo = new ArrayList<>(readLines(appPath));
			
			feature = "";
			for (String s : appInfo){
				if (forceFeatures.size()>0){
					
					if(checkDesiredFeature(s)) {
						feature = cleanString (s);
						features.put(feature, !features.containsKey(feature) ? 1 : features.get(feature)+1);
					}
				} else {
					feature = cleanString (s);
					features.put(feature, !features.containsKey(feature) ? 1 : features.get(feature)+1);
				}			
			}
			
		}
		for(int m=0; m<safeDataSize;m++){
			fileName = safeAppsI.next();
			appPath = debrinPath+fileName;
			dataSetFiles.put(fileName, "safe");
			
			List<String> appInfoSafe = new ArrayList<>(readLines(appPath));
			
			for (String s : appInfoSafe){
				if (forceFeatures.size()>0){
					
					if(checkDesiredFeature(s)) {
						feature = cleanString (s);
						features.put(feature, !features.containsKey(feature) ? 1 : features.get(feature)-1);
					}
				} else {
					feature = cleanString (s);
					features.put(feature, !features.containsKey(feature) ? 1 : features.get(feature)-1);
				}			
			}
	
		}
		
		//Only use features specified in List forceFeatures
		// If array is empty, only use the threshold
		println(" - Total Features: " + features.size());
		
		/* If classifying malware, remove features based on the most frequent features within malware
		 * If the dataset size is 1000 samples, remove any features with a counter greater than
		 * dataset size - threshold
		 * 
		 */
		Map<String, Integer> bestFeatures = new HashMap<String, Integer>();
		if (noClasses.equals("multiclass") ) {
			bestFeatures = features.entrySet().stream()
					.filter(e ->Math.abs(e.getValue())<=datasetSize*1.0)
	                .collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue()));
		} else {
			bestFeatures = features.entrySet().stream()
					.filter(e ->Math.abs(e.getValue())>=thresholdFeatureFilter)
	                .collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue()));
		}
		
		
		Map<String, Integer> featureSort = bestFeatures.entrySet().stream()
                .sorted(Map.Entry.comparingByValue(Comparator.reverseOrder()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
                        (oldValue, newValue) -> oldValue, LinkedHashMap::new));
	    
		println(" - Features left to test: " + bestFeatures.size());
		
		//println("Classes and occurrences: " + keepMalwareClasses);
		//println("Features and occurrences: " + bestFeatures);
		
		/*
		 *  At this point we have a list of features to use - we can now build the dataset
		 *  There will be 2 tests:
		 *  1. Naive Bayes: text classifier, being each app the text to classify based on the feature text
		 *  2. Create a vector of length = n features with the csv format needed for Weka
		 */

			 
			 for (String appFile : dataSetFiles.keySet() ){
				 List<String> myFile = new ArrayList<>(readLines(debrinPath+appFile));
				 List<String> appFeatures = new ArrayList<>();
				 String textContent = "";
				 if (addAppHash){
					 textContent = appFile; 
				 }
				 
				 Iterator <String> bestFI = bestFeatures.keySet().iterator();
				 String bestF = "";
				 while(bestFI.hasNext()){
					 bestF = bestFI.next();
					 if(myFile.toString().contains(bestF)){
						 appFeatures.add(bestF);
					 }
						 
				 }
 
				 for (String f : appFeatures){
					 textContent = textContent + " " + f;
				 }
				 //println(textContent);
				 dataFiles.put(appFile, textContent);
			 }
			  
		// }
		 /* At this point we have clean data and classified data in 2 separate maps
		  * Now write the output for the text classifier as a csv file with 2 columns:
		  * Column 1: class
		  * Column 2: app hash id as the first word and then the concatenated features
		  */
		 String csvLine="";
		 try {
			FileWriter outputDataFW = new FileWriter(outputFileBayes);
			PrintWriter printWriter = new PrintWriter(outputDataFW);
			for(String appHash : dataFiles.keySet()){
				 csvLine = dataSetFiles.get(appHash) + "\t" + dataFiles.get(appHash);
				 printWriter.println(csvLine);
			 }
			printWriter.close();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		 
		 // This is another output as vector format. features are columns
		 String csvLine2="";
		 for (String f : bestFeatures.keySet()){
			 csvLine2 = f + "\t" + csvLine2;
		 }
		 csvLine2 = csvLine2 + "class";
		 
		 try {
			FileWriter outputDataFW = new FileWriter(outputFileWeka);
			PrintWriter printWriter = new PrintWriter(outputDataFW);
			printWriter.println(csvLine2);
			csvLine2="";
			for(String appHash : dataFiles.keySet()){
				for(String f : bestFeatures.keySet()){
					 //csvLine2 = dataSetFiles.get(appHash) + "," + dataFiles.get(appHash);
					 csvLine2 = ((dataFiles.get(appHash).contains(f)) ? "1" : "0") + "\t"+csvLine2;


				 }
				csvLine2 = csvLine2 + "\t" + dataSetFiles.get(appHash);
				printWriter.println(csvLine2.replace("\t\t", "\t"));
				csvLine2="";
			}
			
			printWriter.close();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		 
		 
		
		

		
	}

	
	// Read full document and return lines in a List
	private static List<String> readLines(String pathT){
		List<String> myLines = new ArrayList<>();
		Path path = Paths.get(pathT);
        try (Stream<String> lines = Files.lines(path)) {
    		if (setLowerCase){
    			lines.forEach(s -> myLines.add(s.toLowerCase()));
    		} else {
    			lines.forEach(s -> myLines.add(s));
    		}
        	
        } catch (IOException ex) {
        	println(ex.getMessage());
        }
		return myLines;
	}
	
	private static void println(String s){
		System.out.println(s);
	}
	
	private static void getFileList(){
	File folder = new File(debrinPath);
	File[] listOfFiles = folder.listFiles();

	    for (int i = 0; i < listOfFiles.length; i++) {
	      if (listOfFiles[i].isFile()) {
	    	  fileList.add(listOfFiles[i].getName());
	      } 
	    }
	}
	
	private static String cleanString(String s){
		String cleaned = s.contains("::") ? s.split("::")[1] : s;
		return cleaned.replaceAll("android.", "")
		 .replaceAll("https://", "")
		 .replaceAll("http://", "");
		
	}
	
	private static void writeOutput(String text, FileWriter fw){
		List<String> myLines = new ArrayList<>();
		try (BufferedWriter bw = new BufferedWriter(fw)){
			bw.write(text);
		} catch (IOException e){
			println(e.getMessage());
		}
		
	//	Files.write("/Users/JoseMa/output.txt", text.getBytes());
        
	}
	
	private static boolean checkDesiredFeature(String feature){
		boolean useIt = false;

		for(String f : forceFeatures){
			if (feature.contains(f)){
				useIt = true;
			}
		}
		return useIt;
	}
		
			
	
}
