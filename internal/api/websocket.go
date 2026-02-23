package api

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all for local dashboard
	},
}

// Hub maintains the set of active websocket clients and broadcasts messages.
type Hub struct {
	clients   map[*websocket.Conn]bool
	broadcast chan []byte
	mutex     sync.Mutex
}

func NewHub() *Hub {
	return &Hub{
		broadcast: make(chan []byte, 256),
		clients:   make(map[*websocket.Conn]bool),
	}
}

func (h *Hub) Run() {
	for message := range h.broadcast {
		h.mutex.Lock()
		for client := range h.clients {
			// Set write deadline to prevent blocked clients from hanging the hub
			_ = client.SetWriteDeadline(time.Now().Add(5 * time.Second))
			err := client.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				log.Printf("Websocket write error: %v", err)
				client.Close()
				delete(h.clients, client)
			}
		}
		h.mutex.Unlock()
	}
}

// Subscribe handles incoming websocket connections
func (h *Hub) Subscribe(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("Failed to upgrade websocket: %v", err)
		return
	}

	h.mutex.Lock()
	h.clients[conn] = true
	h.mutex.Unlock()

	log.Printf("New WebSocket client connected. Total clients: %d", len(h.clients))

	// Keep alive loop (we only care about pushing down, but we must read to handle disconnects)
	go func() {
		defer func() {
			h.mutex.Lock()
			delete(h.clients, conn)
			h.mutex.Unlock()
			conn.Close()
			log.Printf("WebSocket client disconnected. Total clients: %d", len(h.clients))
		}()
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("WebSocket error: %v", err)
				}
				break
			}
		}
	}()
}

// Broadcast sends JSON data to all connected clients
func (h *Hub) Broadcast(data []byte) {
	h.broadcast <- data
}
