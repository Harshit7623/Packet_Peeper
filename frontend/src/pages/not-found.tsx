import { Card, CardContent } from "@/components/ui/card";
import { AlertCircle } from "lucide-react";
import { Link } from "wouter";
import { Button } from "@/components/ui/button";
import { motion } from "framer-motion";

export default function NotFound() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-background cyber-grid">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Card className="w-full max-w-md mx-4 bg-card/60 backdrop-blur-xl border-border/50">
          <CardContent className="pt-6">
            <div className="flex items-center mb-4 gap-3">
              <motion.div
                animate={{ rotate: [0, -10, 10, 0] }}
                transition={{ duration: 0.5, repeat: Infinity, repeatDelay: 2 }}
              >
                <AlertCircle className="h-8 w-8 text-destructive" />
              </motion.div>
              <h1 className="text-2xl font-bold text-foreground">404 Page Not Found</h1>
            </div>

            <p className="mt-4 text-sm text-muted-foreground mb-6">
              The page you're looking for doesn't exist or has been moved.
            </p>
            
            <Link href="/">
              <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                <Button className="w-full rounded-full">Return to Dashboard</Button>
              </motion.div>
            </Link>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
