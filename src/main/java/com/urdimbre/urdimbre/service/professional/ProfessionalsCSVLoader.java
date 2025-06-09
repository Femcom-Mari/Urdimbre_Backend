package com.urdimbre.urdimbre.service.professional;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.urdimbre.urdimbre.model.Professional;
import com.urdimbre.urdimbre.repository.ProfessionalsRepository;

import jakarta.annotation.PostConstruct;

@Component
public class ProfessionalsCSVLoader {
    @Autowired
    private ProfessionalsRepository professionalsRepository;

    @PostConstruct
    public void loadProfessionals() throws Exception {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(
                        getClass().getResourceAsStream("/professional/ProfessionalExcel.csv"),
                        StandardCharsets.UTF_8));

        String line;
        boolean firstLine = true;

        while ((line = reader.readLine()) != null) {
            if (firstLine) {
                firstLine = false;
                continue;
            }
            String[] campos = line.split(";");
            if (campos.length < 10)
                continue;

            Professional p = new Professional();
            p.setCiudad(campos[0]);
            p.setNombre(campos[1]);
            p.setDescripcion(campos[2]);
            p.setTelefono(campos[3]);
            p.setEmail(campos[4]);
            p.setWeb(campos[5]);
            p.setRedes(campos[6]);
            p.setPoblacion(campos[7]);
            p.setActividades(campos[8]);
            p.setPrecio(campos[9]);

            professionalsRepository.save(p);

        }
        reader.close();
        System.out.println("Profesionales cargados");

    }
}
