#[macro_use]
extern crate serde;
use candid::{Decode, Encode};
use ic_cdk::api::time;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BoundedStorable, Cell, DefaultMemoryImpl, StableBTreeMap, Storable};
use regex::Regex;
use std::{borrow::Cow, cell::RefCell};

type Memory = VirtualMemory<DefaultMemoryImpl>;
type IdCell = Cell<u64, Memory>;

// UserRole Enum
#[derive(
    candid::CandidType, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Default, Debug,
)]
enum UserRole {
    #[default]
    PetOwner,
    Veterinarian,
    Admin,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct User {
    id: u64,
    username: String,
    email: String,
    phone_number: String,
    role: UserRole,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Pet {
    id: u64,
    owner_id: u64,
    name: String,
    species: String,
    breed: String,
    age: u8,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Appointment {
    id: u64,
    pet_id: u64,
    veterinarian_id: u64,
    date: u64,
    status: String, // "scheduled", "completed", "canceled"
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct HealthRecord {
    id: u64,
    pet_id: u64,
    veterinarian_id: u64,
    record: String,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Prescription {
    id: u64,
    pet_id: u64,
    veterinarian_id: u64,
    medication: String,
    dosage: String,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Message {
    id: u64,
    sender_id: u64,
    recipient_id: u64,
    content: String,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Notification {
    id: u64,
    user_id: u64,
    message: String,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Payment {
    id: u64,
    user_id: u64,
    appointment_id: u64,
    amount: f64,
    status: String, // "pending", "completed", "failed"
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct PetAdoption {
    id: u64,
    pet_id: u64,
    adopter_id: u64,
    status: String, // "available", "adopted"
    created_at: u64,
}

impl Storable for User {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for User {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Pet {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Pet {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Appointment {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Appointment {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for HealthRecord {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for HealthRecord {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Prescription {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Prescription {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Message {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Message {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Notification {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Notification {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Payment {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Payment {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for PetAdoption {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for PetAdoption {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    static ID_COUNTER: RefCell<IdCell> = RefCell::new(
        IdCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), 0)
            .expect("Cannot create a counter")
    );

    static USER_STORAGE: RefCell<StableBTreeMap<u64, User, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
    ));

    static PET_STORAGE: RefCell<StableBTreeMap<u64, Pet, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))
    ));

    static APPOINTMENT_STORAGE: RefCell<StableBTreeMap<u64, Appointment, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))
    ));

    static HEALTH_RECORD_STORAGE: RefCell<StableBTreeMap<u64, HealthRecord, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4)))
    ));

    static PRESCRIPTION_STORAGE: RefCell<StableBTreeMap<u64, Prescription, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5)))
    ));

    static MESSAGE_STORAGE: RefCell<StableBTreeMap<u64, Message, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(6)))
    ));

    static NOTIFICATION_STORAGE: RefCell<StableBTreeMap<u64, Notification, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(7)))
    ));

    static PAYMENT_STORAGE: RefCell<StableBTreeMap<u64, Payment, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(8)))
    ));

    static PET_ADOPTION_STORAGE: RefCell<StableBTreeMap<u64, PetAdoption, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(9)))
    ));
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct UserPayload {
    username: String,
    email: String,
    phone_number: String,
    role: UserRole,
}

// AuthenticatedUserPayload is used to authenticate a user
#[derive(candid::CandidType, Deserialize, Serialize)]
struct AuthenticatedUserPayload {
    username: String,
    role: UserRole,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct PetPayload {
    owner_id: u64,
    name: String,
    species: String,
    breed: String,
    age: u8,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct AppointmentPayload {
    pet_id: u64,
    veterinarian_id: u64,
    date: u64,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct HealthRecordPayload {
    pet_id: u64,
    veterinarian_id: u64,
    record: String,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct PrescriptionPayload {
    pet_id: u64,
    veterinarian_id: u64,
    medication: String,
    dosage: String,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct MessagePayload {
    sender_id: u64,
    recipient_id: u64,
    content: String,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct PaymentPayload {
    user_id: u64,
    appointment_id: u64,
    amount: f64,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct PetAdoptionPayload {
    pet_id: u64,
    adopter_id: u64,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
enum MessageEnum {
    Success(String),
    Error(String),
    NotFound(String),
    InvalidPayload(String),
    UnAuthorized(String),
}

#[ic_cdk::update]
fn create_user(payload: UserPayload) -> Result<User, MessageEnum> {
    // Validate payload to ensure all fields are provided
    if payload.username.is_empty()
        || payload.email.is_empty()
        || payload.phone_number.is_empty()
        || payload.role == UserRole::default()
    {
        return Err(MessageEnum::InvalidPayload(
            "Ensure 'username', 'email', 'phone_number', and 'role' are provided.".to_string(),
        ));
    }

    // Validate the email address format
    let email_regex = Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap();
    if !email_regex.is_match(&payload.email) {
        return Err(MessageEnum::InvalidPayload("Invalid email address".to_string()));
    }

    // Ensure each email is unique
    let email_exists = USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, user)| user.email == payload.email)
    });
    if email_exists {
        return Err(MessageEnum::InvalidPayload("Email already exists".to_string()));
    }

    // Validate the phone number format
    let phone_regex = Regex::new(r"^\+?[0-9]{10,14}$").unwrap();
    if !phone_regex.is_match(&payload.phone_number) {
        return Err(MessageEnum::InvalidPayload("Invalid phone number".to_string()));
    }

    // Ensure the username is unique
    let username_exists = USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, user)| user.username == payload.username)
    });
    if username_exists {
        return Err(MessageEnum::InvalidPayload(
            "Username already exists".to_string(),
        ));
    }

    // Increment the ID counter and create a new user
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let user = User {
        id,
        username: payload.username,
        email: payload.email,
        phone_number: payload.phone_number,
        role: payload.role,
        created_at: current_time(),
    };

    // Insert the user into the storage and return the user
    USER_STORAGE.with(|storage| storage.borrow_mut().insert(id, user.clone()));
    Ok(user)
}

#[ic_cdk::query]
fn get_users() -> Result<Vec<User>, MessageEnum> {
    USER_STORAGE.with(|storage| {
        let users: Vec<User> = storage
            .borrow()
            .iter()
            .map(|(_, user)| user.clone())
            .collect();

        if users.is_empty() {
            Err(MessageEnum::NotFound("No users found".to_string()))
        } else {
            Ok(users)
        }
    })
}

fn authenticate_user(payload: AuthenticatedUserPayload) -> Result<User, MessageEnum> {
    USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, user)| user.username == payload.username && user.role == payload.role)
            .map(|(_, user)| user.clone())
            .ok_or(MessageEnum::UnAuthorized("Invalid credentials".to_string()))
    })
}

#[ic_cdk::update]
fn add_pet(
    payload: PetPayload,
    user_payload: AuthenticatedUserPayload,
) -> Result<Pet, MessageEnum> {
    // Check if the user is a pet owner
    let user = authenticate_user(user_payload)?;
    if user.role != UserRole::PetOwner {
        return Err(MessageEnum::UnAuthorized(
            "You do not have permission to add a pet".to_string(),
        ));
    }

    // Validate payload to ensure all fields are provided
    if payload.name.is_empty() || payload.species.is_empty() || payload.breed.is_empty() {
        return Err(MessageEnum::InvalidPayload(
            "Ensure 'name', 'species', and 'breed' are provided.".to_string(),
        ));
    }

    // Increment the ID counter and create a new pet
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let pet = Pet {
        id,
        owner_id: payload.owner_id,
        name: payload.name,
        species: payload.species,
        breed: payload.breed,
        age: payload.age,
        created_at: current_time(),
    };

    // Insert the pet into the storage and return the pet
    PET_STORAGE.with(|storage| storage.borrow_mut().insert(id, pet.clone()));
    Ok(pet)
}

#[ic_cdk::query]
fn get_pets() -> Result<Vec<Pet>, MessageEnum> {
    PET_STORAGE.with(|storage| {
        let pets: Vec<Pet> = storage
            .borrow()
            .iter()
            .map(|(_, pet)| pet.clone())
            .collect();

        if pets.is_empty() {
            Err(MessageEnum::NotFound("No pets found".to_string()))
        } else {
            Ok(pets)
        }
    })
}

#[ic_cdk::update]
fn schedule_appointment(
    payload: AppointmentPayload,
    user_payload: AuthenticatedUserPayload,
) -> Result<Appointment, MessageEnum> {
    // Check if the user is a pet owner
    let user = authenticate_user(user_payload)?;
    if user.role != UserRole::PetOwner {
        return Err(MessageEnum::UnAuthorized(
            "You do not have permission to schedule an appointment".to_string(),
        ));
    }

    // Validate payload to ensure all fields are provided
    if payload.date == 0 {
        return Err(MessageEnum::InvalidPayload(
            "Ensure 'date' is provided.".to_string(),
        ));
    }

    // Increment the ID counter and create a new appointment
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let appointment = Appointment {
        id,
        pet_id: payload.pet_id,
        veterinarian_id: payload.veterinarian_id,
        date: payload.date,
        status: "scheduled".to_string(),
        created_at: current_time(),
    };

    // Insert the appointment into the storage and return the appointment
    APPOINTMENT_STORAGE.with(|storage| storage.borrow_mut().insert(id, appointment.clone()));
    Ok(appointment)
}

#[ic_cdk::query]
fn get_appointments() -> Result<Vec<Appointment>, MessageEnum> {
    APPOINTMENT_STORAGE.with(|storage| {
        let appointments: Vec<Appointment> = storage
            .borrow()
            .iter()
            .map(|(_, appointment)| appointment.clone())
            .collect();

        if appointments.is_empty() {
            Err(MessageEnum::NotFound("No appointments found".to_string()))
        } else {
            Ok(appointments)
        }
    })
}

#[ic_cdk::update]
fn add_health_record(
    payload: HealthRecordPayload,
    user_payload: AuthenticatedUserPayload,
) -> Result<HealthRecord, MessageEnum> {
    // Check if the user is a veterinarian
    let user = authenticate_user(user_payload)?;
    if user.role != UserRole::Veterinarian {
        return Err(MessageEnum::UnAuthorized(
            "You do not have permission to add a health record".to_string(),
        ));
    }

    // Validate payload to ensure all fields are provided
    if payload.record.is_empty() {
        return Err(MessageEnum::InvalidPayload(
            "Ensure 'record' is provided.".to_string(),
        ));
    }

    // Increment the ID counter and create a new health record
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let health_record = HealthRecord {
        id,
        pet_id: payload.pet_id,
        veterinarian_id: payload.veterinarian_id,
        record: payload.record,
        created_at: current_time(),
    };

    // Insert the health record into the storage and return the health record
    HEALTH_RECORD_STORAGE.with(|storage| storage.borrow_mut().insert(id, health_record.clone()));
    Ok(health_record)
}

#[ic_cdk::query]
fn get_health_records() -> Result<Vec<HealthRecord>, MessageEnum> {
    HEALTH_RECORD_STORAGE.with(|storage| {
        let health_records: Vec<HealthRecord> = storage
            .borrow()
            .iter()
            .map(|(_, health_record)| health_record.clone())
            .collect();

        if health_records.is_empty() {
            Err(MessageEnum::NotFound("No health records found".to_string()))
        } else {
            Ok(health_records)
        }
    })
}

#[ic_cdk::update]
fn add_prescription(
    payload: PrescriptionPayload,
    user_payload: AuthenticatedUserPayload,
) -> Result<Prescription, MessageEnum> {
    // Check if the user is a veterinarian
    let user = authenticate_user(user_payload)?;
    if user.role != UserRole::Veterinarian {
        return Err(MessageEnum::UnAuthorized(
            "You do not have permission to add a prescription".to_string(),
        ));
    }

    // Validate payload to ensure all fields are provided
    if payload.medication.is_empty() || payload.dosage.is_empty() {
        return Err(MessageEnum::InvalidPayload(
            "Ensure 'medication' and 'dosage' are provided.".to_string(),
        ));
    }

    // Increment the ID counter and create a new prescription
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let prescription = Prescription {
        id,
        pet_id: payload.pet_id,
        veterinarian_id: payload.veterinarian_id,
        medication: payload.medication,
        dosage: payload.dosage,
        created_at: current_time(),
    };

    // Insert the prescription into the storage and return the prescription
    PRESCRIPTION_STORAGE.with(|storage| storage.borrow_mut().insert(id, prescription.clone()));
    Ok(prescription)
}

#[ic_cdk::query]
fn get_prescriptions() -> Result<Vec<Prescription>, MessageEnum> {
    PRESCRIPTION_STORAGE.with(|storage| {
        let prescriptions: Vec<Prescription> = storage
            .borrow()
            .iter()
            .map(|(_, prescription)| prescription.clone())
            .collect();

        if prescriptions.is_empty() {
            Err(MessageEnum::NotFound("No prescriptions found".to_string()))
        } else {
            Ok(prescriptions)
        }
    })
}

#[ic_cdk::update]
fn send_message(payload: MessagePayload) -> Result<Message, MessageEnum> {
    // Validate payload to ensure all fields are provided
    if payload.content.is_empty() {
        return Err(MessageEnum::InvalidPayload(
            "Ensure 'content' is provided.".to_string(),
        ));
    }

    // Increment the ID counter and create a new message
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let message = Message {
        id,
        sender_id: payload.sender_id,
        recipient_id: payload.recipient_id,
        content: payload.content,
        created_at: current_time(),
    };

    // Insert the message into the storage and return the message
    MESSAGE_STORAGE.with(|storage| storage.borrow_mut().insert(id, message.clone()));
    Ok(message)
}

#[ic_cdk::query]
fn get_messages() -> Result<Vec<Message>, MessageEnum> {
    MESSAGE_STORAGE.with(|storage| {
        let messages: Vec<Message> = storage
            .borrow()
            .iter()
            .map(|(_, message)| message.clone())
            .collect();

        if messages.is_empty() {
            Err(MessageEnum::NotFound("No messages found".to_string()))
        } else {
            Ok(messages)
        }
    })
}

#[ic_cdk::update]
fn send_notification(
    user_id: u64,
    message: String,
    user_payload: AuthenticatedUserPayload,
) -> Result<Notification, MessageEnum> {
    // Authenticate the user
    let user = authenticate_user(user_payload)?;

    // Check if the user is an admin
    if user.role != UserRole::Admin {
        return Err(MessageEnum::UnAuthorized(
            "You do not have permission to send a notification".to_string(),
        ));
    }

    // Increment the ID counter and create a new notification
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let notification = Notification {
        id,
        user_id,
        message,
        created_at: current_time(),
    };

    // Insert the notification into the storage and return the notification
    NOTIFICATION_STORAGE.with(|storage| {
        storage
            .borrow_mut()
            .insert(id, notification.clone())
    });
    Ok(notification)
}

#[ic_cdk::query]
fn get_notifications() -> Result<Vec<Notification>, MessageEnum> {
    NOTIFICATION_STORAGE.with(|storage| {
        let notifications: Vec<Notification> = storage
            .borrow()
            .iter()
            .map(|(_, notification)| notification.clone())
            .collect();

        if notifications.is_empty() {
            Err(MessageEnum::NotFound("No notifications found".to_string()))
        } else {
            Ok(notifications)
        }
    })
}

#[ic_cdk::update]
fn process_payment(
    payload: PaymentPayload,
    // user_payload: AuthenticatedUserPayload,
) -> Result<Payment, MessageEnum> {
    // Authenticate the user
    // let user = authenticate_user(user_payload)?;

    // Validate payload to ensure all fields are provided
    if payload.amount <= 0.0 {
        return Err(MessageEnum::InvalidPayload(
            "Ensure 'amount' is provided and greater than zero.".to_string(),
        ));
    }

    // Increment the ID counter and create a new payment
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let payment = Payment {
        id,
        user_id: payload.user_id,
        appointment_id: payload.appointment_id,
        amount: payload.amount,
        status: "pending".to_string(),
        created_at: current_time(),
    };

    // Insert the payment into the storage and return the payment
    PAYMENT_STORAGE.with(|storage| storage.borrow_mut().insert(id, payment.clone()));
    Ok(payment)
}

#[ic_cdk::query]
fn get_payments() -> Result<Vec<Payment>, MessageEnum> {
    PAYMENT_STORAGE.with(|storage| {
        let payments: Vec<Payment> = storage
            .borrow()
            .iter()
            .map(|(_, payment)| payment.clone())
            .collect();

        if payments.is_empty() {
            Err(MessageEnum::NotFound("No payments found".to_string()))
        } else {
            Ok(payments)
        }
    })
}

#[ic_cdk::update]
fn add_pet_for_adoption(
    payload: PetAdoptionPayload,
    user_payload: AuthenticatedUserPayload,
) -> Result<PetAdoption, MessageEnum> {
    // Authenticate the user
    let user = authenticate_user(user_payload)?;

    // Check if the user is an admin
    if user.role != UserRole::Admin {
        return Err(MessageEnum::UnAuthorized(
            "You do not have permission to add a pet for adoption".to_string(),
        ));
    }

    // Increment the ID counter and create a new pet adoption record
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let pet_adoption = PetAdoption {
        id,
        pet_id: payload.pet_id,
        adopter_id: payload.adopter_id,
        status: "available".to_string(),
        created_at: current_time(),
    };

    // Insert the pet adoption record into the storage and return the record
    PET_ADOPTION_STORAGE.with(|storage| storage.borrow_mut().insert(id, pet_adoption.clone()));
    Ok(pet_adoption)
}

#[ic_cdk::query]
fn get_pet_adoptions() -> Result<Vec<PetAdoption>, MessageEnum> {
    PET_ADOPTION_STORAGE.with(|storage| {
        let pet_adoptions: Vec<PetAdoption> = storage
            .borrow()
            .iter()
            .map(|(_, pet_adoption)| pet_adoption.clone())
            .collect();

        if pet_adoptions.is_empty() {
            Err(MessageEnum::NotFound("No pet adoptions found".to_string()))
        } else {
            Ok(pet_adoptions)
        }
    })
}

fn current_time() -> u64 {
    time()
}

#[derive(candid::CandidType, Deserialize, Serialize)]
enum Error {
    NotFound { msg: String },
    UnAuthorized { msg: String },
}

ic_cdk::export_candid!();
