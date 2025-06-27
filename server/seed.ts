import { storage } from "./storage";
import { hashPassword } from "./auth";

export async function seedDatabase() {
  try {
    // Create demo company first
    const company = await storage.createCompany({
      name: "Tech Solutions Inc.",
      description: "Technology consulting company",
      isActive: true,
    });

    console.log("Created demo company:", company);

    // Create Super Admin
    const superAdmin = await storage.createUser({
      email: "superadmin@system.com",
      password: await hashPassword("admin123"),
      firstName: "Super",
      lastName: "Admin",
      role: "super_admin",
      companyId: null,
      isActive: true,
    });

    console.log("Created super admin:", superAdmin.email);

    // Create Company Admin
    const companyAdmin = await storage.createUser({
      email: "admin@techsolutions.com",
      password: await hashPassword("admin123"),
      firstName: "Company",
      lastName: "Admin",
      role: "company_admin",
      companyId: company.id,
      isActive: true,
      createdBy: superAdmin.id,
    });

    console.log("Created company admin:", companyAdmin.email);

    // Create Employee
    const employee = await storage.createUser({
      email: "john.doe@techsolutions.com",
      password: await hashPassword("employee123"),
      firstName: "John",
      lastName: "Doe",
      role: "employee",
      companyId: company.id,
      isActive: true,
      createdBy: companyAdmin.id,
    });

    console.log("Created employee:", employee.email);

    // Create additional employee
    const employee2 = await storage.createUser({
      email: "jane.smith@techsolutions.com",
      password: await hashPassword("employee123"),
      firstName: "Jane",
      lastName: "Smith",
      role: "employee",
      companyId: company.id,
      isActive: true,
      createdBy: companyAdmin.id,
    });

    console.log("Created employee:", employee2.email);

    console.log("Database seeded successfully!");
    
    return {
      company,
      superAdmin,
      companyAdmin,
      employee,
      employee2,
    };
  } catch (error) {
    console.error("Error seeding database:", error);
    throw error;
  }
}