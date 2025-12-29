#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cuda_runtime.h>

#define MAX_PW 100000
#define ENC_LEN 11     // 10 chars + null
#define RAW_LEN 5      // 2 letters + 2 digits + null
#define TOTAL 67600    // 26*26*10*10

__device__ void encrypt(const char *rawPassword, char *newPassword) {
	newPassword[0] = rawPassword[0] + 2;
    newPassword[1] = rawPassword[0] - 2;
	newPassword[2] = rawPassword[0] + 1;
	newPassword[3] = rawPassword[1] + 3;
	newPassword[4] = rawPassword[1] - 3;
	newPassword[5] = rawPassword[1] - 1;
	newPassword[6] = rawPassword[2] + 2;
	newPassword[7] = rawPassword[2] - 2;
	newPassword[8] = rawPassword[3] + 4;
	newPassword[9] = rawPassword[3] - 4;
	newPassword[10] = '\0';

    for(int i =0; i<10; i++){
		if(i >= 0 && i < 6){ 
			if(newPassword[i] > 122){
				newPassword[i] = (newPassword[i] - 122) + 97;
			}else if(newPassword[i] < 97){
				newPassword[i] = (97 - newPassword[i]) + 97;
			}
		}else{
			if(newPassword[i] > 57){
				newPassword[i] = (newPassword[i] - 57) + 48;
			}else if(newPassword[i] < 48){
				newPassword[i] = (48 - newPassword[i]) + 48;
			}
		}
	}
}

__device__ int match(const char *a, const char *b) {
    for (int i = 0; i < 10; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

__global__ void crack(const char *enc_list, int npw, char *results, int *found) {
    long long gid = (long long)blockIdx.x * blockDim.x + threadIdx.x;
    long long totalWork = (long long)npw * (long long)TOTAL;
    if (gid >= totalWork) return;
    int p = (int)(gid / TOTAL);
    int idx = (int)(gid % TOTAL);
    if (found[p]) return;

    // generate candidate
    int temp = idx;
    char digit1 = '0' + (temp % 10); temp /= 10;
    char digit10 = '0' + (temp % 10); temp /= 10;
    char letter1 = 'a' + (temp % 26); temp /= 26;
    char letter0 = 'a' + temp;

    char raw[RAW_LEN] = {letter0, letter1, digit10, digit1, 0};
    char candidate[ENC_LEN];
    encrypt(raw, candidate);
    
    const char *target = enc_list + p * ENC_LEN;

    if (match(candidate, target)) {
        if (atomicCAS(&found[p], 0, 1) == 0) {
            char *out = results + p * RAW_LEN;
            out[0] = raw[0];
            out[1] = raw[1];
            out[2] = raw[2];
            out[3] = raw[3];
            out[4] = '\0';
        }
    }
}


int load_file(const char *fname, char **data, int *count) {
    FILE *f = fopen(fname, "r");
    if (!f) { perror("open"); return 1; }

    *data = (char*)malloc(MAX_PW * ENC_LEN);
    *count = 0;

    char buf[32];
    while (fgets(buf, sizeof(buf), f) && *count < MAX_PW) {
        if (strlen(buf) >= 10) {
            buf[strcspn(buf, "\n")] = 0;
            strcpy(*data + (*count) * ENC_LEN, buf);
            (*count)++;
        }
    }
    fclose(f);
    return 0;
}

int save_results(char *results, int n) {
    FILE *f = fopen("decrypted.txt", "w");
    if (!f) return 1;

    for (int i = 0; i < n; i++) {
        char *pw = results + i * RAW_LEN;
        if (pw[0]) fprintf(f, "%s\n", pw);
    }
    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <encrypted_file>\n", argv[0]);
        return 1;
    }

    char *h_enc = NULL;
    int npw = 0;
    if (load_file(argv[1], &h_enc, &npw)) return 1;
    if (npw == 0) { free(h_enc); return 1; }

    printf("Loaded %d passwords, starting crack...\n", npw);

    char *d_enc, *d_res;
    int *d_found;

    cudaMalloc(&d_enc, npw * ENC_LEN);
    cudaMalloc(&d_res, npw * RAW_LEN);
    cudaMalloc(&d_found, npw * sizeof(int));

    cudaMemcpy(d_enc, h_enc, npw * ENC_LEN, cudaMemcpyHostToDevice);
    cudaMemset(d_res, 0, npw * RAW_LEN);
    cudaMemset(d_found, 0, npw * sizeof(int));

    int threads = 256;
    long long totalWork = (long long)npw * (long long)TOTAL;
    int blocks = (int)((totalWork + threads - 1) / threads);

    crack<<<blocks, threads>>>(d_enc, npw, d_res, d_found);

    cudaDeviceSynchronize();

    char *results = (char*)malloc(npw * RAW_LEN);
    cudaMemcpy(results, d_res, npw * RAW_LEN, cudaMemcpyDeviceToHost);

    save_results(results, npw);

    printf("Done! Check decrypted.txt\n");

    // cleanup
    cudaFree(d_enc); cudaFree(d_res); cudaFree(d_found);
    free(h_enc); free(results);

    return 0;
}