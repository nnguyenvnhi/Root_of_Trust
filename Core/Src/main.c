/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2023 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "fatfs.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "time.h"
#include "ed25519.h"
#include "sha3.h"
#include "ge.h"
#include "sc.h"
#include "ChaCha20.h"
#include "stdio.h"
#include "Ex_Flash.h"
#include "W25Qxx.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
#define FLASH_SLOT_0_ADD	0x08020000
#define FLASH_SLOT_1_ADD	0x08060000
#define FLASH_SLOT_2_ADD	0x080A0000

typedef enum{
	FLASH_SLOT_0 = 0x00, //bootloader
	FLASH_SLOT_1, //app1
	FLASH_SLOT_2  //app2
}defFlashSlot;

typedef enum{
    HANDLE_OK = 0x00,
    HANDLE_FAILED
}defReturnType;
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
SD_HandleTypeDef hsd;

SPI_HandleTypeDef hspi2;

TIM_HandleTypeDef htim1;

UART_HandleTypeDef huart4;
UART_HandleTypeDef huart1;
UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_SDIO_SD_Init(void);
static void MX_USART1_UART_Init(void);
static void MX_UART4_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_TIM1_Init(void);
static void MX_SPI2_Init(void);
/* USER CODE BEGIN PFP */
static uint32_t total_time = 0;
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
static void goto_application(uint32_t slotadd)
{
//  printf("Gonna Jump to Application\r\n");

  void (*app_reset_handler)(void) = (void*)(*((volatile uint32_t*) (slotadd + 4U)));

//  __set_MSP(*(volatile uint32_t*) 0x08020000);

  // Turn OFF the Green Led to tell the user that Bootloader is not running
//  HAL_GPIO_WritePin(GPIOB, GPIO_PIN_0, GPIO_PIN_RESET );    //Green LED OFF
  app_reset_handler();    //call the app reset handler
}


HAL_StatusTypeDef sd_init(){
	if(BSP_SD_Init() == MSD_OK ) return HAL_OK;
	else return HAL_ERROR;
}

FRESULT sd_mount(FATFS *fatfs){
	return f_mount(fatfs, "", 1);
}

FRESULT sd_open(FIL *myfile, const char *file_name, uint8_t mode){
	return f_open(myfile, file_name, mode);
}

UINT sd_write(FIL *myfile, const uint8_t *write_buf, uint16_t size){
		UINT bw;
		f_write (myfile, write_buf, size, &bw);
		return bw;
}

uint32_t sd_read(FIL *myfile, uint8_t *read_buf, uint32_t size){
	uint32_t br = 0;
	f_read(myfile, read_buf, size,(UINT*) &br);
	return br;
}

void sd_close(FIL *myfile){
	f_close(myfile);
}

void store_into_flash(uint8_t* buffer, uint32_t address, uint16_t size){
	for(uint16_t s = 0; s < size; s++){
		HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, address, *(buffer));
		address++;
		buffer++;
	}
}

defReturnType init_flash(uint8_t slot){
	defReturnType ret;

	ret = HAL_FLASH_Unlock();
	if(ret != (uint8_t)HAL_OK){
		return HANDLE_FAILED;
	}

	FLASH_EraseInitTypeDef EraseInitStruct;
	uint32_t SectorError;

	EraseInitStruct.TypeErase     = FLASH_TYPEERASE_SECTORS;

	if(slot == 0x00){
		EraseInitStruct.Sector        = FLASH_SECTOR_5;
	}
	else if(slot == 0x01){
		EraseInitStruct.Sector        = FLASH_SECTOR_7;
	}
	else if(slot == 0x02){
		EraseInitStruct.Sector        = FLASH_SECTOR_9;
	}
	EraseInitStruct.NbSectors     = 2;           //erase 2 sectors
	EraseInitStruct.VoltageRange  = FLASH_VOLTAGE_RANGE_3;

	ret = HAL_FLASHEx_Erase( &EraseInitStruct, &SectorError );
	if( ret != (uint8_t)HAL_OK )
	{
		return HANDLE_FAILED;
	}

	return HANDLE_OK;
}
uint32_t read_file_and_store_into_flash(FATFS *fatfs, FIL *myfile, const char *file_name, uint8_t mode, defFlashSlot slot, uint8_t *signature, uint8_t *publickey, uint8_t *hashvalue){

	uint32_t BaseAddress;
	if(sd_init() == HAL_ERROR) return HAL_ERROR;
//	HAL_GPIO_WritePin(GPIOE, GPIO_PIN_0, GPIO_PIN_SET);
	if(sd_mount(fatfs) != FR_OK) return HAL_ERROR;
//	HAL_GPIO_WritePin(GPIOE, GPIO_PIN_1, GPIO_PIN_SET);
	if(sd_open(myfile, file_name, mode) != FR_OK) return HAL_ERROR;
//	HAL_GPIO_WritePin(GPIOE, GPIO_PIN_2, GPIO_PIN_SET);
	uint32_t size_file = f_size(myfile) - 160;

	if(init_flash(slot) != HANDLE_OK) return HAL_ERROR;
//	HAL_GPIO_WritePin(GPIOE, GPIO_PIN_3, GPIO_PIN_SET);

	if(slot == FLASH_SLOT_0) BaseAddress = FLASH_SLOT_0_ADD;
	else if(slot == FLASH_SLOT_1) BaseAddress = FLASH_SLOT_1_ADD;
	else if(slot == FLASH_SLOT_2) BaseAddress = FLASH_SLOT_2_ADD;
	else{}

//	HAL_GPIO_WritePin(GPIOE, GPIO_PIN_4, GPIO_PIN_SET);
	uint16_t round = size_file/1024; round += (size_file%1024 != 0)?1:0;

	uint8_t buffer_cipher[1024] = {0,};
	uint8_t buffer_plaintext[1024] = {0,};

	if(sd_read(myfile, signature, 64) != 64) return HAL_ERROR;
	if(sd_read(myfile, publickey, 32) != 32) return HAL_ERROR;
	if(sd_read(myfile, hashvalue, 64) != 64) return HAL_ERROR;

	for(uint16_t r = 0; r < round - 1; r++){
		if(sd_read(myfile, buffer_cipher, 1024) != 1024) return HAL_ERROR;
		Chacha20_Xor(Gb_scKeyStream, Gb_sulCell, buffer_cipher, 1024, buffer_plaintext);
		store_into_flash(buffer_plaintext, BaseAddress + r*1024, 1024);
		memset(buffer_cipher,0,1024);
		memset(buffer_plaintext,0,1024);
	}

//	HAL_GPIO_WritePin(GPIOE, GPIO_PIN_5, GPIO_PIN_SET);

	if(sd_read(myfile, buffer_cipher, size_file%1024) != size_file%1024) return HAL_ERROR;
	Chacha20_Xor(Gb_scKeyStream, Gb_sulCell, buffer_cipher, size_file%1024, buffer_plaintext);
	store_into_flash(buffer_plaintext, BaseAddress + (round - 1)*1024, size_file%1024);
//	HAL_GPIO_WritePin(GPIOE, GPIO_PIN_7, GPIO_PIN_SET);

	sd_close(myfile);
	HAL_FLASH_Lock();

	return size_file;
}

void read_chunk_data_in_flash(uint8_t *buf, uint32_t address, uint16_t size){
	for(uint32_t index = 0; index< size ; index++){
		*buf = *(__IO uint8_t *)(address + index);
		buf++;
	}
}

HAL_StatusTypeDef tree_hash_on_flash(defFlashSlot slot, uint8_t* md, uint32_t size){
	uint16 round = size/1024; round += (size%64 != 0)?1:0;
	uint8_t buff_hash[round][64];
	uint32_t BaseAddress;

	if(slot == FLASH_SLOT_0) BaseAddress = FLASH_SLOT_0_ADD;
	else if(slot == FLASH_SLOT_1) BaseAddress = FLASH_SLOT_1_ADD;
	else if(slot == FLASH_SLOT_2) BaseAddress = FLASH_SLOT_2_ADD;
	else{}


	for(uint16 i = 0;i<round - 1;i++){
		uint8 buff_file[1024] = {0,};
		read_chunk_data_in_flash(buff_file, BaseAddress + i*1024, 1024);
		sha3(buff_file,1024, &buff_hash[i], 64);
	}

	uint8_t buff_file[1024] = {0,};
	read_chunk_data_in_flash(buff_file, BaseAddress + (round-1)*1024, size%1024);

	sha3(buff_file, size%1024, &buff_hash[round-1], 64);


	uint8_t all_of_hash[round*64];
	for(uint16 i = 0; i< round; i++){
		for(uint16 j = 0;j<64;j++){
			all_of_hash[i*64+j] = buff_hash[i][j];
		}
	}

	sha3(all_of_hash, round*64, md, 64);


	return HAL_OK;
}

uint8_t read_reset_cause(){
	HAL_FLASH_Unlock();
	uint8_t reset_cause = ((*((__IO uint32 *)0x080E0000))&0x00000100)>>8;
	HAL_FLASH_Lock();
	return reset_cause;

}

//defReturnType init_flash(uint8_t slot); //call only one time.
//HAL_StatusTypeDef sd_init();
//FRESULT sd_mount(FATFS *fatfs);
//FRESULT sd_open(FIL *myfile, const char *file_name, uint8_t mode);
//UINT sd_write(FIL *myfile, const uint8_t *write_buf, uint16_t size);
//uint32_t sd_read(FIL *myfile, uint8_t *read_buf,  uint32_t size);
//void sd_close(FIL *myfile);
//
//void store_into_flash(uint8_t* buffer, uint32_t address, uint16_t size);
//void read_chunk_data_in_flash(uint8_t *buf, uint32_t address, uint16_t size);
//uint32_t read_file_and_store_into_flash(FATFS *fatfs, FIL *myfile, const char *file_name, uint8_t mode, defFlashSlot slot, uint8_t *signature, uint8_t *publickey, uint8_t *hashvalue);
//HAL_StatusTypeDef tree_hash_on_flash(defFlashSlot slot, uint8_t* md, uint32_t size);

uint32_t size = 0;
uint8_t md[64], signature[64], publickey[32], hashvaluer[64], sig[64], pub[32], hashval[64];
FRESULT f1,f2,f3;
uint8_t buffer[160] = {0,};

void Update_Signature(Certificate *cert, uint8_t* signature){
	for(uint8_t index = 0; index < 64; index++){
		cert->signature[index] = signature[index];
	}
}

void Update_Publickey(Certificate *cert, uint8_t* publickey){
	for(uint8_t index = 0;index < 32; index++){
		cert->publickey[index] = publickey[index];
	}
}
void Update_HashValue(Certificate *cert, uint8_t* hashvalue){
	for(uint8_t index = 0;index < 32; index++){
			cert->hash[index] = hashvalue[index];
	}
}

void Update_BootloaderCert(uint8_t* signature, uint8_t* publickey, uint8_t* hashvalue){
	Update_Signature(&Bootloader_Cert, signature);
	Update_Publickey(&Bootloader_Cert, publickey);
	Update_HashValue(&Bootloader_Cert, hashvalue);
}

void Update_Application1Cert(uint8_t* signature, uint8_t* publickey, uint8_t* hashvalue){
	Update_Signature(&Application1_Cert, signature);
	Update_Publickey(&Application1_Cert, publickey);
	Update_HashValue(&Application1_Cert, hashvalue);
}

void Update_Application2Cert(uint8_t* signature, uint8_t* publickey, uint8_t* hashvalue){
	Update_Signature(&Application2_Cert, signature);
	Update_Publickey(&Application2_Cert, publickey);
	Update_HashValue(&Application2_Cert, hashvalue);
}

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_SDIO_SD_Init();
  MX_FATFS_Init();
  MX_USART1_UART_Init();
  MX_UART4_Init();
  MX_USART2_UART_Init();
  MX_TIM1_Init();
  MX_SPI2_Init();
  /* USER CODE BEGIN 2 */
  HAL_TIM_Base_Start(&htim1);
  uint16_t time = 0;
  uint32_t total_time = 0;
  FATFS fatfs; FIL myfile;
//  uint8_t sig[64], pub[32], has[64];
//  W25qxx_Init();
//    	  for(uint8_t i = 0;i<64;i++){
//    		  sig[i] = i + 1;
//    		  has[i] = i + 2;
//
//    	  }
//    	  for (uint8_t i = 0;i<32;i++){
//    		  pub[i] = i + 3;
//    	  }
//
//    	  Update_BootloaderCert(sig, pub, has);
//  W25qxx_EraseSector(1);
//  read_file_and_store_into_flash(&fatfs, &myfile, "boot.bin", FA_READ, FLASH_SLOT_0, signature, publickey, hashvaluer);
//  Update_BootloaderCert(signature, publickey, hashvaluer);
//  W25qxx_WriteSector(Bootloader_Cert.signature, 1, 0, 64);
//  W25qxx_WriteSector(Bootloader_Cert.publickey, 1, 64, 32);
//  W25qxx_WriteSector(Bootloader_Cert.hash, 1, 96, 64);
//
//  W25qxx_EraseSector(2);
//  read_file_and_store_into_flash(&fatfs, &myfile, "appa.bin", FA_READ, FLASH_SLOT_1, signature, publickey, hashvaluer);
//  Update_Application1Cert(signature, publickey, hashvaluer);
//  W25qxx_WriteSector(Application1_Cert.signature, 2, 0, 64);
//  W25qxx_WriteSector(Application1_Cert.publickey, 2, 64, 32);
//  W25qxx_WriteSector(Application1_Cert.hash, 2, 96, 64);
//
//  W25qxx_ReadSector(buffer, 1, 0, 160);

  if(read_reset_cause()) {
	  HAL_GPIO_WritePin(GPIOD, GPIO_PIN_14, GPIO_PIN_SET);
	  goto_application(FLASH_SLOT_0_ADD);
  }
  HAL_UART_Transmit(&huart2, "\r*****THIS IS ROT PROGRAM*****\n\r", 32, 1000);
  uint8_t buffer[100] = {0,};
  TIM1->CNT = 0;
  size = read_file_and_store_into_flash(&fatfs, &myfile, "boot.bin", FA_READ, FLASH_SLOT_0, signature, publickey, hashvaluer);
  time = TIM1->CNT;
  total_time += time;
  HAL_UART_Transmit(&huart2, "\r       -READ BOOTLOADER AND STORE IN FLASH\n\r", 50, 1000);
  sprintf(buffer, "\r              +SIZE: %d BYTES\n\r              +TIME: %.2f(MS)\n\r", size, (float)time/5.0);
  HAL_UART_Transmit(&huart2, buffer, 100, 1000);
  memset(buffer, 0, 100);
  TIM1->CNT = 0;
  tree_hash_on_flash(FLASH_SLOT_0, md, size);
  time = TIM1->CNT;
  total_time += time;
  HAL_UART_Transmit(&huart2, "\r       -TREE HASH IN FLASH\n\r", 28, 1000);
  sprintf(buffer, "\r              +TIME: %.2f(MS)\n\r", (float)time/5.0);
  HAL_UART_Transmit(&huart2, buffer, 40, 1000);
  memset(buffer, 0, 100);
  TIM1->CNT = 0;
  W25qxx_Init();
  W25qxx_ReadSector(sig, 1, ADDRESS_STORE_BOOTLOADER_CERT , 64);
  W25qxx_ReadSector(pub, 1, ADDRESS_STORE_BOOTLOADER_CERT + 64, 32);
  W25qxx_ReadSector(hashval, 1, ADDRESS_STORE_BOOTLOADER_CERT + 32 + 64, 64);
  if (ed25519_verify(sig, md, 64, pub)) {
	  time = TIM1->CNT;
	  total_time += time;
	  HAL_UART_Transmit(&huart2, "\r       -VERIFY BOOTLOADER SUCCESSFULL\n\r", 50, 1000);
	  sprintf(buffer, "\r              +TIME: %.2f(MS)\n\r", (float)time/5.0);
	  HAL_UART_Transmit(&huart2, buffer, 40, 1000);
	  sprintf(buffer, "\r       -TOTAL TIME: %.2f(MS)\n\r", (float)total_time/5.0);
	  HAL_UART_Transmit(&huart2, buffer, 40, 1000);
	  goto_application(FLASH_SLOT_0_ADD);
	  HAL_GPIO_WritePin(GPIOD, GPIO_PIN_14, GPIO_PIN_SET);
  } else {
	  HAL_GPIO_WritePin(GPIOD, GPIO_PIN_14, GPIO_PIN_SET);
	  Error_Handler();
  }

//	sd_init();
//	f1 = sd_mount(&fatfs);
//	f2 = sd_open(&myfile, "boot.bin", FA_READ);
//	sd_read(&myfile, publickey, 32);
//	sd_close(&myfile);

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
//	  HAL_Delay(200);
//	  HAL_GPIO_WritePin(GPIOD, GPIO_PIN_14, GPIO_PIN_SET);
//	  goto_application(FLASH_SLOT_1_ADD);
//	  HAL_GPIO_TogglePin(GPIOD, GPIO_PIN_15);
//	  HAL_Delay(100);
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);
  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM = 8;
  RCC_OscInitStruct.PLL.PLLN = 168;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 4;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }
  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief SDIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_SDIO_SD_Init(void)
{

  /* USER CODE BEGIN SDIO_Init 0 */

  /* USER CODE END SDIO_Init 0 */

  /* USER CODE BEGIN SDIO_Init 1 */

  /* USER CODE END SDIO_Init 1 */
  hsd.Instance = SDIO;
  hsd.Init.ClockEdge = SDIO_CLOCK_EDGE_RISING;
  hsd.Init.ClockBypass = SDIO_CLOCK_BYPASS_DISABLE;
  hsd.Init.ClockPowerSave = SDIO_CLOCK_POWER_SAVE_DISABLE;
  hsd.Init.BusWide = SDIO_BUS_WIDE_1B;
  hsd.Init.HardwareFlowControl = SDIO_HARDWARE_FLOW_CONTROL_DISABLE;
  hsd.Init.ClockDiv = 2;
  /* USER CODE BEGIN SDIO_Init 2 */

  /* USER CODE END SDIO_Init 2 */

}

/**
  * @brief SPI2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_SPI2_Init(void)
{

  /* USER CODE BEGIN SPI2_Init 0 */

  /* USER CODE END SPI2_Init 0 */

  /* USER CODE BEGIN SPI2_Init 1 */

  /* USER CODE END SPI2_Init 1 */
  /* SPI2 parameter configuration*/
  hspi2.Instance = SPI2;
  hspi2.Init.Mode = SPI_MODE_MASTER;
  hspi2.Init.Direction = SPI_DIRECTION_2LINES;
  hspi2.Init.DataSize = SPI_DATASIZE_8BIT;
  hspi2.Init.CLKPolarity = SPI_POLARITY_LOW;
  hspi2.Init.CLKPhase = SPI_PHASE_1EDGE;
  hspi2.Init.NSS = SPI_NSS_SOFT;
  hspi2.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_2;
  hspi2.Init.FirstBit = SPI_FIRSTBIT_MSB;
  hspi2.Init.TIMode = SPI_TIMODE_DISABLE;
  hspi2.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
  hspi2.Init.CRCPolynomial = 10;
  if (HAL_SPI_Init(&hspi2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN SPI2_Init 2 */

  /* USER CODE END SPI2_Init 2 */

}

/**
  * @brief TIM1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_TIM1_Init(void)
{

  /* USER CODE BEGIN TIM1_Init 0 */

  /* USER CODE END TIM1_Init 0 */

  TIM_ClockConfigTypeDef sClockSourceConfig = {0};
  TIM_MasterConfigTypeDef sMasterConfig = {0};

  /* USER CODE BEGIN TIM1_Init 1 */

  /* USER CODE END TIM1_Init 1 */
  htim1.Instance = TIM1;
  htim1.Init.Prescaler = 33600-1;
  htim1.Init.CounterMode = TIM_COUNTERMODE_UP;
  htim1.Init.Period = 65535;
  htim1.Init.ClockDivision = TIM_CLOCKDIVISION_DIV1;
  htim1.Init.RepetitionCounter = 0;
  htim1.Init.AutoReloadPreload = TIM_AUTORELOAD_PRELOAD_DISABLE;
  if (HAL_TIM_Base_Init(&htim1) != HAL_OK)
  {
    Error_Handler();
  }
  sClockSourceConfig.ClockSource = TIM_CLOCKSOURCE_INTERNAL;
  if (HAL_TIM_ConfigClockSource(&htim1, &sClockSourceConfig) != HAL_OK)
  {
    Error_Handler();
  }
  sMasterConfig.MasterOutputTrigger = TIM_TRGO_RESET;
  sMasterConfig.MasterSlaveMode = TIM_MASTERSLAVEMODE_DISABLE;
  if (HAL_TIMEx_MasterConfigSynchronization(&htim1, &sMasterConfig) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN TIM1_Init 2 */

  /* USER CODE END TIM1_Init 2 */

}

/**
  * @brief UART4 Initialization Function
  * @param None
  * @retval None
  */
static void MX_UART4_Init(void)
{

  /* USER CODE BEGIN UART4_Init 0 */

  /* USER CODE END UART4_Init 0 */

  /* USER CODE BEGIN UART4_Init 1 */

  /* USER CODE END UART4_Init 1 */
  huart4.Instance = UART4;
  huart4.Init.BaudRate = 9600;
  huart4.Init.WordLength = UART_WORDLENGTH_8B;
  huart4.Init.StopBits = UART_STOPBITS_1;
  huart4.Init.Parity = UART_PARITY_NONE;
  huart4.Init.Mode = UART_MODE_TX_RX;
  huart4.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart4.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart4) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN UART4_Init 2 */

  /* USER CODE END UART4_Init 2 */

}

/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 9600;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */

}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 9600;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOD_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOB, GPIO_PIN_12, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOD, GPIO_PIN_12|GPIO_PIN_13|GPIO_PIN_14|GPIO_PIN_15, GPIO_PIN_RESET);

  /*Configure GPIO pin : PB12 */
  GPIO_InitStruct.Pin = GPIO_PIN_12;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

  /*Configure GPIO pins : PD12 PD13 PD14 PD15 */
  GPIO_InitStruct.Pin = GPIO_PIN_12|GPIO_PIN_13|GPIO_PIN_14|GPIO_PIN_15;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOD, &GPIO_InitStruct);

}

/* USER CODE BEGIN 4 */




/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */

