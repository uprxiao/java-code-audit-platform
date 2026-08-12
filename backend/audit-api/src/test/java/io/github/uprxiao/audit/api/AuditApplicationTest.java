package io.github.uprxiao.audit.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class AuditApplicationTest {

    @Autowired
    MockMvc mvc;

    @Test
    void contextLoads() {
    }

    @Test
    void rejectsEmptyUploadUsingTheStableApiErrorContract() throws Exception {
        MockMultipartFile empty = new MockMultipartFile("source", "empty.zip", "application/zip", new byte[0]);

        mvc.perform(multipart("/api/v1/scans/zip").file(empty))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
                .andExpect(jsonPath("$.requestId").isNotEmpty());
    }

    @Test
    void rejectsMalformedRequestJsonAsBadRequest() throws Exception {
        MockMultipartFile source = new MockMultipartFile(
                "source", "project.zip", "application/zip", new byte[]{1});
        MockMultipartFile request = new MockMultipartFile(
                "request", "", MediaType.APPLICATION_JSON_VALUE, "{bad-json".getBytes());

        mvc.perform(multipart("/api/v1/scans/zip").file(source).file(request))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    void rejectsForbiddenSvnTransportBeforeCreatingAJob() throws Exception {
        mvc.perform(post("/api/v1/scans/svn")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"repositoryUrl\":\"svn+ssh://example.test/repository\",\"profile\":\"QUICK\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("UNSUPPORTED_SVN_PROTOCOL"));
    }

    @Test
    void rejectsSvnUrlUserInfoAndNonSnapshotRevision() throws Exception {
        mvc.perform(post("/api/v1/scans/svn")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"repositoryUrl\":\"https://alice:secret@example.test/repository\",\"profile\":\"QUICK\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_SVN_URL"));

        mvc.perform(post("/api/v1/scans/svn")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"repositoryUrl\":\"https://example.test/repository\",\"revision\":\"1:9\",\"profile\":\"QUICK\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_SVN_REVISION"));
    }
}
