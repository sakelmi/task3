#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cuda_runtime.h>

#define MAX_PASSWORDS 100000
#define ENCRYPTED_LEN 11        // 10 chars + null terminator
#define PLAIN_LEN     5         // aa00 + null
#define TOTAL_CANDIDATES 67600  // 26*26*10*10

__device__ void encrypt_password(const char *plain, char *encrypted)
{
    encrypted[0] = plain[0] + 2;
    encrypted[1] = plain[0] - 2;
    encrypted[2] = plain[0] + 1;
    encrypted[3] = plain[1] + 3;
    encrypted[4] = plain[1] - 3;
    encrypted[5] = plain[1] - 1;
    encrypted[6] = plain[2] + 2;
    encrypted[7] = plain[2] - 2;
    encrypted[8] = plain[3] + 4;
    encrypted[9] = plain[3] - 4;
    encrypted[10] = '\0';

    for (int i = 0; i < 10; i++) {
        if (i < 6) {  // letters
            if (encrypted[i] > 'z')
                encrypted[i] = (encrypted[i] - 'z') + 'a';
            else if (encrypted[i] < 'a')
                encrypted[i] = ('a' - encrypted[i]) + 'a';
        } else {      // digits
            if (encrypted[i] > '9')
                encrypted[i] = (encrypted[i] - '9') + '0';
            else if (encrypted[i] < '0')
                encrypted[i] = ('0' - encrypted[i]) + '0';
        }
    }
}

__device__ int passwords_match(const char *a, const char *b)
{
    for (int i = 0; i < 10; i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

__global__ void crack_kernel(const char *encrypted_list, int num_passwords,
                            char *results, int *found_flags)
{
    long long global_id = (long long)blockIdx.x * blockDim.x + threadIdx.x;
    long long total_work = (long long)num_passwords * TOTAL_CANDIDATES;

    if (global_id >= total_work)
        return;

    int pw_index = global_id / TOTAL_CANDIDATES;
    int cand_index = global_id % TOTAL_CANDIDATES;

    if (found_flags[pw_index])
        return;  // already cracked by another thread

    // Generate candidate: format like "ab12"
    int temp = cand_index;
    char d1 = '0' + (temp % 10); temp /= 10;
    char d0 = '0' + (temp % 10); temp /= 10;
    char l1 = 'a' + (temp % 26); temp /= 26;
    char l0 = 'a' + temp;

    char plain[PLAIN_LEN] = { l0, l1, d0, d1, '\0' };

    char candidate[ENCRYPTED_LEN];
    encrypt_password(plain, candidate);

    const char *target = encrypted_list + pw_index * ENCRYPTED_LEN;

    if (passwords_match(candidate, target)) {
        if (atomicCAS(&found_flags[pw_index], 0, 1) == 0) {
            char *out = results + pw_index * PLAIN_LEN;
            out[0] = l0;
            out[1] = l1;
            out[2] = d0;
            out[3] = d1;
            out[4] = '\0';
        }
    }
}

int load_encrypted(const char *filename, char **data, int *count)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open file");
        return 1;
    }

    *data = (char *)malloc(MAX_PASSWORDS * ENCRYPTED_LEN);
    if (!*data) {
        fclose(fp);
        return 1;
    }

    *count = 0;
    char line[64];

    while (fgets(line, sizeof(line), fp) && *count < MAX_PASSWORDS) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) >= 10) {
            strcpy(*data + (*count) * ENCRYPTED_LEN, line);
            (*count)++;
        }
    }

    fclose(fp);
    return 0;
}

int write_results(const char *results, int count)
{
    FILE *fp = fopen("decrypted.txt", "w");
    if (!fp) {
        perror("Failed to create decrypted.txt");
        return 1;
    }

    for (int i = 0; i < count; i++) {
        const char *pw = results + i * PLAIN_LEN;
        if (pw[0] != '\0')  // only write if found
            fprintf(fp, "%s\n", pw);
    }

    fclose(fp);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <encrypted_file.txt>\n", argv[0]);
        return 1;
    }

    char *host_encrypted = NULL;
    int num_passwords = 0;

    if (load_encrypted(argv[1], &host_encrypted, &num_passwords)) {
        return 1;
    }

    if (num_passwords == 0) {
        printf("No valid passwords found in file.\n");
        free(host_encrypted);
        return 0;
    }

    printf("Loaded %d encrypted passwords. Starting brute-force...\n", num_passwords);

    char *d_encrypted, *d_results;
    int *d_found;

    cudaMalloc(&d_encrypted, num_passwords * ENCRYPTED_LEN);
    cudaMalloc(&d_results,   num_passwords * PLAIN_LEN);
    cudaMalloc(&d_found,     num_passwords * sizeof(int));

    cudaMemcpy(d_encrypted, host_encrypted, num_passwords * ENCRYPTED_LEN, cudaMemcpyHostToDevice);
    cudaMemset(d_results, 0, num_passwords * PLAIN_LEN);
    cudaMemset(d_found,   0, num_passwords * sizeof(int));

    int threads_per_block = 256;
    long long total_threads_needed = (long long)num_passwords * TOTAL_CANDIDATES;
    int num_blocks = (total_threads_needed + threads_per_block - 1) / threads_per_block;

    crack_kernel<<<num_blocks, threads_per_block>>>(d_encrypted, num_passwords, d_results, d_found);

    cudaDeviceSynchronize();

    char *host_results = (char *)malloc(num_passwords * PLAIN_LEN);
    cudaMemcpy(host_results, d_results, num_passwords * PLAIN_LEN, cudaMemcpyDeviceToHost);

    write_results(host_results, num_passwords);

    printf("Cracking complete. Results saved to decrypted.txt\n");

    // Cleanup
    cudaFree(d_encrypted);
    cudaFree(d_results);
    cudaFree(d_found);
    free(host_encrypted);
    free(host_results);

    return 0;
}
