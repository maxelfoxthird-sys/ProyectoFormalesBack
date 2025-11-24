from db import db
#01 , 04, 05, 06, 07 y uno incorrecto los demas viene de lexico qeu tenemos en postamn
#archivo de una ejecicion, ya se puede elimnar si es reqeurido 
"""
tokens = [
    {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmb28iLCJuYW1lIjoiSm9obiBEb2UifQ.e-SNBBoq5GLibwWoGdM933jWX0ipYFNqJJA0tpU26YU", "valido": True},
    {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmb28iLCJuYW1lIjoiSm9obiBEb2UifQ.XM-XSs2Lmp76IcTQ7tVdFcZzN4W_WcoKMNANp925Q9g", "valido": True},
    {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FwaS5taS1wcm95ZWN0by5jb20iLCJzdWIiOiJhdXRoMHwxMjM0NTY3ODkwIiwiYXVkIjoiaHR0cHM6Ly9hcGkubWktcHJveWVjdG8uY29tL3YxIiwiaWF0IjoxNzYyOTU2MDAwLCJleHAiOjE3NjI5NTk2MDAsIm5iZiI6MTc2Mjk1NjAwMCwianRpIjoiYWJjLWRlZi0xMjMiLCJ1c2VybmFtZSI6Impvc2Uuc2FsYW1hbmNhIiwicm9sZSI6ImFkbWluIn0.Vq2-vG1A-PzX3Yy_G-m-9S-k4_x-D2k-c6y-T-M8_Vw", "valido": True},
    {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FwaS5taS1wcm95ZWN0by5jb20iLCJzdWIiOiJhdXRoMHwwOTg3NjU0MzIxIiwiYXVkIjoiaHR0cHM6Ly9hcGkubWktcHJveWVjdG8uY29tL3YxIiwiaWF0IjoxNzYyOTQ4ODAwLCJleHAiOjE3NjI5NTI0MDAsIm5iZiI6MTc2Mjk0ODgwMCwianRpIjoiZ2hpLWprbC00NTYiLCJ1c2VybmFtZSI6InNhbXVlbC51c2VyIiwicm9sZSI6InVzZXIifQ.J-Z_y_T-B_J-d_v-E_c-g_g-V_l-f_j-M_v-r_y-B_Q", "valido": True},
    {"token": "eyJhbGciOiJIU380IiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2F1dGgubWktcHJveWVjdG8uY29tIiwic3ViIjoiZ29vZ2xlLW9hdXRoMnwxMTIyMzM0NDU1IiwiYXVkIjpbImh0dHBzOi8vYXBpLm1pLXByb3llY3RvLmNvbS92MSIsImh0dHBzOi8vYWRtaW4ubWktcHJveWVjdG8uY29tIl0sImlhdCI6MTc2Mjk1NjAwMCwiZXhwIjoxNzYyOTU5NjAwLCJqdGkiOiJtbm8tcHFyLTc4OSIsImVtYWlsIjoidGVzdEBnbWFpbC5jb20iLCJwZXJtaXNzaW9ucyI6WyJyZWFkOmRhdGEiLCJ3cml0ZTpkYXRhIl19.K-i-h_j-J_y-k_w-s_v-q_v-H_P-C_T-S_V-W_Y-v_P-H_w-y_k-L_o-X_m", "valido": True},
    {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmb28iLCJuYW1lIjoiSm9obiBEb2UifQ", "valido": False, "tipo_error": "Incorrecto formato JWT (Inompleto)"},
]

db.JWTS.insert_many(tokens)

"""
print("JWTs insertados")
