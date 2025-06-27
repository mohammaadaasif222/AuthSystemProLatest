import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Play, Trash2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface DatabaseQueryInterfaceProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function DatabaseQueryInterface({ open, onOpenChange }: DatabaseQueryInterfaceProps) {
  const [query, setQuery] = useState("SELECT * FROM users WHERE role = 'company_admin';");
  const [results, setResults] = useState<any>(null);
  const { toast } = useToast();

  const executeQueryMutation = useMutation({
    mutationFn: async (sqlQuery: string) => {
      const res = await apiRequest("POST", "/api/database/query", { query: sqlQuery });
      return res.json();
    },
    onSuccess: (result) => {
      setResults(result);
      if (result.status === "error") {
        toast({
          title: "Query Error",
          description: result.message,
          variant: "destructive",
        });
      } else {
        toast({
          title: "Query Executed",
          description: `Query executed successfully. ${result.rows} rows affected.`,
        });
      }
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleExecuteQuery = () => {
    if (query.trim()) {
      executeQueryMutation.mutate(query);
    }
  };

  const handleClearQuery = () => {
    setQuery("");
    setResults(null);
  };

  const sampleQueries = [
    "SELECT * FROM users WHERE role = 'company_admin';",
    "SELECT u.id, u.email, u.role, u.first_name, u.last_name, c.name as company_name FROM users u LEFT JOIN companies c ON u.company_id = c.id ORDER BY u.role, c.name;",
    "SELECT COUNT(*) as total_employees FROM users WHERE role = 'employee';",
    "SELECT c.name, COUNT(u.id) as employee_count FROM companies c LEFT JOIN users u ON c.id = u.company_id AND u.role = 'employee' GROUP BY c.id, c.name;",
    "SELECT m.id, s.first_name || ' ' || s.last_name as sender_name, m.message_type, m.content, m.created_at FROM messages m JOIN users s ON m.sender_id = s.id ORDER BY m.created_at DESC LIMIT 10;"
  ];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-6xl max-h-[90vh] overflow-hidden">
        <DialogHeader>
          <DialogTitle>Database Query Interface</DialogTitle>
          <DialogDescription>
            Execute SQL queries for development and testing. Be careful with destructive operations.
          </DialogDescription>
        </DialogHeader>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 h-[600px]">
          <div className="flex flex-col h-full">
            <div className="flex justify-between items-center mb-2">
              <Label htmlFor="query">SQL Query</Label>
              <div className="flex gap-2">
                <Button
                  onClick={handleExecuteQuery}
                  disabled={!query.trim() || executeQueryMutation.isPending}
                  className="bg-blue-600 hover:bg-blue-700"
                  size="sm"
                >
                  <Play className="h-4 w-4 mr-1" />
                  Execute
                </Button>
                <Button
                  onClick={handleClearQuery}
                  variant="outline"
                  size="sm"
                >
                  <Trash2 className="h-4 w-4 mr-1" />
                  Clear
                </Button>
              </div>
            </div>
            
            <Textarea
              id="query"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Enter your SQL query here..."
              className="flex-1 font-mono text-sm resize-none"
            />
            
            <div className="mt-4">
              <Label>Sample Queries</Label>
              <div className="mt-2 space-y-1 max-h-32 overflow-y-auto">
                {sampleQueries.map((sampleQuery, index) => (
                  <Button
                    key={index}
                    variant="ghost"
                    size="sm"
                    className="w-full text-left justify-start h-auto p-2 text-xs"
                    onClick={() => setQuery(sampleQuery)}
                  >
                    <code className="truncate">{sampleQuery}</code>
                  </Button>
                ))}
              </div>
            </div>
          </div>
          
          <div className="flex flex-col h-full">
            <div className="flex justify-between items-center mb-2">
              <Label>Query Results</Label>
              {results && (
                <span className="text-sm text-gray-500">
                  {results.status === "success" ? `${results.rows} rows` : "Error"}
                </span>
              )}
            </div>
            
            <div className="flex-1 border border-gray-300 rounded-lg p-4 bg-gray-50 overflow-auto">
              {executeQueryMutation.isPending ? (
                <div className="text-center text-gray-500">Executing query...</div>
              ) : results ? (
                <pre className="text-sm text-gray-700 whitespace-pre-wrap">
                  {JSON.stringify(results, null, 2)}
                </pre>
              ) : (
                <div className="text-center text-gray-500">
                  Execute a query to see results here
                </div>
              )}
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
