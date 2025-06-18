package com.urdimbre.urdimbre.loader;

import org.springframework.boot.CommandLineRunner;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Component
public class ProfessionalUploader implements CommandLineRunner {

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final String API_URL = "http://localhost:8080/professionals";

    @Override
    public void run(String... args) throws Exception {
        InputStream inputStream = getClass().getResourceAsStream("/professionals_transformed_updated.csv");
        if (inputStream == null) {
            System.err.println("❌ CSV not found.");
            return;
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
        String header = reader.readLine(); // Skip header
        String line;

        int success = 0;
        int failed = 0;

        while ((line = reader.readLine()) != null) {
            String[] parts = line.split(",", -1);

            Map<String, Object> dto = new HashMap<>();
            dto.put("name", parts[0]);
            dto.put("city", parts[1]);
            dto.put("pronouns", parts[2].isEmpty() ? List.of() : Arrays.asList(parts[2].split("\\|")));
            dto.put("description", parts[3]);
            dto.put("phone", parts[4]);
            dto.put("email", parts[5]);
            dto.put("website", parts[6]);
            dto.put("socialMedia", parts[7]);
            dto.put("town", parts[8]);
            dto.put("activities", parts[9]);
            dto.put("price", parts[10]);
            dto.put("communityStatus", parts[11]);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<String> request = new HttpEntity<>(objectMapper.writeValueAsString(dto), headers);

            try {
                ResponseEntity<String> response = restTemplate.postForEntity(API_URL, request, String.class);
                System.out.println("✅ Sent: " + dto.get("name") + " → " + response.getStatusCode());
                success++;
            } catch (Exception e) {
                System.err.println("❌ Error sending " + dto.get("name") + ": " + e.getMessage());
                failed++;
            }
        }

        System.out.println("🏁 Done. Uploaded: " + success + " | Failed: " + failed);
    }
}
