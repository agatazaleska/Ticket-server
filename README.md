## Ticket_server

# Project description

This is a project task for "Computer Networks" course at University of Warsaw, the Faculty of Mathematics, Informatics and Mechanics, 2021/2022.
I do not own the idea for this project.

The program is a UDP server that handles network ticket reservation for events.

Server parameters:  
-f file - the path to the file containing the description of available events  
-p port - the port on which the server listens (by default, 2022)  
-t timeout - the time limit for collecting the tickets (in seconds)  

The client may send the following commands to the server:  

GET_EVENTS  
GET_RESERVATION, event_id, ticket_count > 0  
GET_TICKETS, reservation_id, cookie  

The client may receive the following answers from the server:  

EVENTS  
RESERVATION, reservation_id, event_id, ticket_count, cookie, expiration_time  
TICKETS, reservation_id, ticket_count > 0, ticket, ..., ticket  
BAD_REQUEST, event_id or reservation_id  
